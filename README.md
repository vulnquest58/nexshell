# NexShell v2 — Unified Pentest Operations Platform

<div align="center">

```
   ███╗   ██╗███████╗██╗  ██╗███████╗██╗  ██╗███████╗██╗     ██╗
   ████╗  ██║██╔════╝╚██╗██╔╝██╔════╝██║  ██║██╔════╝██║     ██║
   ██╔██╗ ██║█████╗   ╚███╔╝ ███████╗███████║█████╗  ██║     ██║
   ██║╚██╗██║██╔══╝   ██╔██╗ ╚════██║██╔══██║██╔══╝  ██║     ██║
   ██║ ╚████║███████╗██╔╝ ██╗███████║██║  ██║███████╗███████╗███████╗
   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
              Nexus of Shell Operations  ·  v2 — Operations Platform
```

![Python](https://img.shields.io/badge/Python-3.8+-purple?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-2.0.0-blueviolet)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)
![License](https://img.shields.io/badge/License-MIT-lime)
![Author](https://img.shields.io/badge/Author-vulnquest58-orange)
![Files](https://img.shields.io/badge/Files-51%20Python%20%7C%20650KB-red)
![Lines](https://img.shields.io/badge/Lines-15%2C560-green)
![Commands](https://img.shields.io/badge/CLI%20Commands-57-orange)

</div>

> **NexShell v2** is a **Unified Pentest Operations Platform** — managing sessions, assets, findings, evidence, transport channels, operation scope, credential inventory, timelines, and real-time web dashboards from a single REPL interface. Zero external dependencies except the stdlib.

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
| Plugin system | ❌ | ✅ |
| Rule engine (8 built-in rules) | ❌ | ✅ |
| Report generation (MD/HTML/JSON) | ❌ | ✅ |
| Health monitor + analytics | ❌ | ✅ |
| OPSEC profiles (ghost/paranoid) | basic | ✅ full |
| Event bus (async pub/sub) | ❌ | ✅ |

---

## Architecture

```
nexshell/
├── nexshell.py           # Main REPL — 57 CLI commands, 3,600+ lines
│
├── core/                 # Framework kernel
│   ├── event_bus.py      # Async pub/sub event dispatcher
│   ├── plugin.py         # NexPlugin base + auto-discovery registry
│   ├── rules.py          # Rule engine — 8 auto-detection rules
│   ├── scheduler.py      # Priority task queue + background workers
│   └── workflow.py       # DAG workflow engine — 4 built-in workflows
│
├── db/                   # SQLite persistence layer
│   ├── database.py       # NexDB — full CRUD for all entities
│   └── schema_v2.py      # Schema: hosts, findings, operations, evidence
│
├── modules/              # Transport + utilities
│   ├── transport.py      # TLS listener + HTTP tunnel v1
│   ├── transport/        # v2 enhanced transport package
│   │   ├── http_tunnel.py  # HTTP covert channel (XOR, multi-agent, jitter)
│   │   └── websocket.py    # RFC 6455 WebSocket (multi-client, ping/pong)
│   ├── loot.py           # Loot collection → SQLite
│   ├── session_manager.py
│   └── ...
│
├── web/                  # Real-time Web Dashboard (stdlib only)
│   ├── server.py         # HTTP + WebSocket combined server
│   └── templates/
│       ├── index.html    # Dark-mode dashboard — 7 views
│       ├── style.css     # Premium CSS — CSS vars, animations
│       └── app.js        # Real-time WS client + REST fallback
│
├── operations/           # Engagement management
│   ├── operation.py      # Operation workspace (scope, objectives)
│   ├── scope.py          # CIDR scope manager + in/out-of-scope check
│   ├── timeline.py       # Engagement timeline — 10 event types
│   └── checklist.py      # Pentest (25 items) + CTF (10 items) checklists
│
├── inventory/            # Asset intelligence
│   ├── hosts.py          # HostInventory + FindingsManager + attack graph
│   ├── services.py       # ServiceInventory — 60+ port maps, nmap parser
│   ├── credentials.py    # CredentialStore — dedup, type detect, crack track
│   └── tags.py           # Tagging system
│
├── knowledge/            # OSINT + reference knowledge
│   ├── mitre.py          # MITRE ATT&CK (30+ TTPs) + PlaybookEngine
│   └── notes.py          # Persistent notes — search, pin, tag, export
│
├── evidence/             # Chain of custody
│   └── collector.py      # SHA256 hash, timestamp, ZIP export
│
├── reports/              # Report generation
│   └── reporter.py       # Markdown + HTML + JSON output
│
├── config/               # Configuration management
│   ├── profiles.py       # 3 OPSEC profiles + 4 operator roles
│   └── templates.py      # 4 engagement templates
│
├── services/             # Platform services
│   └── health.py         # Health monitor + analytics engine
│
├── models/               # Shared data models
│   └── __init__.py       # Host, Service, Finding, Evidence, Operation
│
└── plugins/              # Auto-discovered plugins
    └── example_quickenum.py
```

---

## Quick Start

```bash
git clone https://github.com/vulnquest58/nexshell
cd nexshell
python nexshell.py
```

```
(NexShell)> help          # Show all 57 commands
(NexShell)> web start     # Launch real-time dashboard → http://localhost:8888
(NexShell)> health        # System health check
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
| `plugins` | List loaded plugins |
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
| Findings | Security findings with severity filter |
| Loot | Collected loot with category/source |
| MITRE ATT&CK | Observed techniques heatmap |
| Operation | Current engagement details |

**Features:**
- Real-time WebSocket push (every 3 seconds)
- REST API fallback (`/api/snapshot`, `/api/sessions`, etc.)
- EventBus wiring — findings/sessions/loot appear instantly
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

# Python stdlib agent
(NexShell)> transport agent python 10.10.14.1 8080 /api/ping

# WebSocket agent (Linux)
(NexShell)> transport agent ws 10.10.14.1 9001 /

# WebSocket agent (Python, cross-platform)
(NexShell)> transport agent ws-python 10.10.14.1 9001 /
```

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

## Plugin Development

```python
from core.plugin import NexPlugin

class MyPlugin(NexPlugin):
    name        = "my_plugin"
    description = "Does something useful"
    author      = "you"
    version     = "1.0"

    def on_session_connect(self, session):
        """Auto-runs when a new session connects."""
        output = self.exec("id; whoami; hostname")
        self.loot(output, category="auto_enum")
        self.finding("Low", "Plugin ran", self.session.host)
        self.emit("plugin.ran", plugin=self.name)
```

Drop the file in `plugins/` — it's auto-discovered on startup.

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
| `finding.created` | Security finding added |
| `host.added` | New host discovered |
| `cred.discovered` | Credential found |
| `timeline.event` | Engagement event added |
| `rule.triggered` | Rule engine match |

---

## Database

SQLite database at `nexshell.db` — zero configuration needed.

```bash
(NexShell)> db stats           # Show record counts
(NexShell)> db search loot admin   # Search loot
(NexShell)> db export          # Export full JSON dump
(NexShell)> db vacuum          # VACUUM (compact DB)
```

**Schema tables:** `sessions`, `loot`, `hosts`, `findings`, `operations`, `evidence`, `operation_scope`, `operation_objectives`

---

## Stats

```
51 Python files  ·  3 web files  ·  15,560 lines  ·  650 KB
20 phases         ·  57 CLI commands  ·  8/8 tests passing
```

---

## License

MIT License — for authorized security testing only.

> ⚠️ Use only on systems you own or have explicit written permission to test.
