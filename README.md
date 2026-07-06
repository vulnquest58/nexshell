# NexShell v2 — Unified Pentest Operations Platform

<div align="center">

```
   ███╗   ██╗███████╗██╗  ██╗███████╗██╗  ██╗███████╗██╗     ██╗
   ████╗  ██║██╔════╝╚██╗██╔╝██╔════╝██║  ██║██╔════╝██║     ██║
   ██╔██╗ ██║█████╗   ╚███╔╝ ███████╗███████║█████╗  ██║     ██║
   ██║╚██╗██║██╔══╝   ██╔██╗ ╚════██║██╔══██║██╔══╝  ██║     ██║
   ██║ ╚████║███████╗██╔╝ ██╗███████║██║  ██║███████╗███████╗███████╗
   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
              Nexus of Shell Operations  ·  v2 — Professional Operations Platform
```

![Python](https://img.shields.io/badge/Python-3.8+-purple?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-2.0.0-blueviolet)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)
![License](https://img.shields.io/badge/License-MIT-lime)
![Author](https://img.shields.io/badge/Author-vulnquest58-orange)
![Files](https://img.shields.io/badge/Files-52%20Python%20%7C%20700KB-red)
![Lines](https://img.shields.io/badge/Lines-19%2C000%2B-green)
![Commands](https://img.shields.io/badge/CLI%20Commands-57-orange)
![Plugins](https://img.shields.io/badge/Plugins-11%20Professional-crimson)

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
| **11 Professional Plugins** | ❌ | ✅ |
| **Cloud/K8s/AD/Container coverage** | ❌ | ✅ |
| **2025-2026 CVE detection** | ❌ | ✅ |

---

## Architecture

```
nexshell/
├── nexshell.py              # Main REPL — 57 CLI commands, 3,600+ lines
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
└── plugins/                 # Auto-discovered professional plugins (11 total)
    ├── auto_enum_linux.py   # Linux post-exploitation enumeration v3.0
    ├── auto_enum_windows.py # Windows post-exploitation enumeration v3.0
    ├── privesc_scanner.py   # Linux privilege escalation scanner v3.0
    ├── cred_hunter.py       # Multi-source credential hunter v3.0
    ├── network_scout.py     # Network discovery + banner grabbing v3.0
    ├── persistence_check.py # Persistence mechanism detection v3.0
    ├── cloud_recon.py       # Cloud environment recon (AWS/GCP/Azure/K8s) v1.0
    ├── ad_attack.py         # Active Directory attack suite v1.0
    ├── container_escape.py  # Container/K8s escape detection v1.0
    ├── lateral_mover.py     # Lateral movement vector assessment v1.0
    └── example_quickenum.py # Example plugin template v1.0
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

---

## Professional Plugin Engine

NexShell v2 ships with **11 professional-grade plugins** organized in two waves.
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

## CLI Commands (57 total)

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

---

## Stats

```
52 Python files  ·  3 web files  ·  19,000+ lines  ·  ~700 KB
20 platform phases  ·  57 CLI commands  ·  11 professional plugins
8/8 tests passing  ·  0 external dependencies
```

---

## License

MIT License — for authorized security testing only.

> ⚠️ Use only on systems you own or have explicit written permission to test.
> This tool is intended for professional penetration testers and security researchers.
