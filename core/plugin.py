#!/usr/bin/env python3
"""
NexShell — Plugin Base Class  (core/plugin.py)
Drop-in module system: place any NexPlugin subclass in plugins/
and it's auto-discovered on startup.

Usage:
    # plugins/my_module.py
    from core.plugin import NexPlugin

    class MyModule(NexPlugin):
        name        = "my-module"
        description = "Custom post-exploitation for XYZ"
        author      = "operator"
        version     = "1.0"
        platform    = "linux"       # linux | windows | all
        category    = "recon"       # recon | persist | lateral | exfil | custom
        mitre_id    = "T1087"       # optional MITRE ATT&CK ID

        def run(self, session, args: list):
            output = session.exec("id")
            self.loot(output, category="credentials", source="id_cmd")
            self.finding("Low privilege user", severity="info")
            return output
"""

import os
import sys
import importlib
import importlib.util
import logging
import inspect
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger('nexshell.plugins')


# ══════════════════════════════════════════════════════════════════════════════
#  BASE PLUGIN
# ══════════════════════════════════════════════════════════════════════════════

class NexPlugin:
    """Base class for all NexShell plugins."""

    name:        str = ""           # CLI name: 'run my-module'
    description: str = ""          # Short description
    author:      str = "unknown"   # Author
    version:     str = "1.0"
    platform:    str = "all"       # linux | windows | all
    category:    str = "custom"    # recon | persist | lateral | exfil | custom
    mitre_id:    str = ""          # MITRE ATT&CK technique ID

    # Injected by PluginRegistry on load
    _session = None
    _db      = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def setup(self):
        """Called once when the plugin is loaded. Override to init resources."""
        pass

    def run(self, session, args: list) -> Optional[str]:
        """
        Main entry point. Override this in your plugin.
        Return output string or None.
        """
        raise NotImplementedError(f"Plugin '{self.name}' must implement run()")

    def teardown(self):
        """Called when plugin is unloaded."""
        pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def loot(self, data: str, category: str = "custom", source: str = "",
             confidence: str = "high"):
        """Convenience: add loot to the DB from within a plugin."""
        if not data:
            return
        try:
            from db import get_db
            host = getattr(self._session, 'host', '') if self._session else ''
            sid  = getattr(self._session, 'id',   0)  if self._session else 0
            get_db().add_loot(
                category=category, data=data, source=source or self.name,
                host=host, session_id=sid, confidence=confidence,
            )
        except Exception as e:
            logger.debug(f"Plugin loot error: {e}")

    def finding(self, title: str, description: str = "", severity: str = "info",
                cvss: float = 0.0, recommendation: str = ""):
        """Convenience: create a finding from within a plugin."""
        try:
            from db import get_db
            host = getattr(self._session, 'host', '') if self._session else ''
            sid  = getattr(self._session, 'id',   0)  if self._session else 0
            db   = get_db()
            if hasattr(db, 'add_finding'):
                db.add_finding(
                    title=title, description=description,
                    severity=severity, cvss=cvss,
                    recommendation=recommendation,
                    host=host, session_id=sid,
                    source=self.name,
                )
        except Exception as e:
            logger.debug(f"Plugin finding error: {e}")

    def emit(self, event_name: str, **data):
        """Publish an event to the EventBus."""
        try:
            from core.event_bus import bus
            bus.emit(event_name, plugin=self.name, **data)
        except Exception:
            pass

    def info(self, msg: str):
        logger.info(f"[{self.name}] {msg}")

    def warn(self, msg: str):
        logger.warning(f"[{self.name}] {msg}")

    def error(self, msg: str):
        logger.error(f"[{self.name}] {msg}")

    @classmethod
    def meta(cls) -> dict:
        return {
            'name':        cls.name,
            'description': cls.description,
            'author':      cls.author,
            'version':     cls.version,
            'platform':    cls.platform,
            'category':    cls.category,
            'mitre_id':    cls.mitre_id,
        }

    def _exec(self, session, cmd: str, timeout: int = 10) -> str:
        """Execute a command on the remote session and return output string."""
        for method_name in ('exec', 'run', 'execute', 'send_command'):
            fn = getattr(session, method_name, None)
            if not callable(fn):
                continue
            try:
                try:
                    result = fn(cmd, timeout=timeout, value=True)
                except TypeError:
                    result = fn(cmd)
                if result is None:
                    continue
                if isinstance(result, bytes):
                    return result.decode(errors='replace')
                if isinstance(result, str):
                    return result
            except Exception:
                pass
        return ''


# ══════════════════════════════════════════════════════════════════════════════
#  PLUGIN REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

class PluginRegistry:
    """
    Auto-discovers and loads NexPlugin subclasses from a plugins/ directory.
    Supports hot-reload without restarting NexShell.
    """

    def __init__(self, plugin_dir: Optional[str] = None):
        self._dir:     Path                  = Path(plugin_dir or 'plugins').resolve()
        self._plugins: Dict[str, NexPlugin]  = {}   # name → instance
        self._classes: Dict[str, type]       = {}   # name → class

    def discover(self) -> List[str]:
        """Scan plugin_dir and load all NexPlugin subclasses. Returns list of loaded names."""
        if not self._dir.exists():
            self._dir.mkdir(parents=True, exist_ok=True)
            return []

        loaded = []
        for path in sorted(self._dir.glob("*.py")):
            if path.name.startswith('_'):
                continue
            try:
                names = self._load_file(path)
                loaded.extend(names)
            except Exception as e:
                logger.warning(f"Failed to load plugin {path.name}: {e}")
        return loaded

    def _load_file(self, path: Path) -> List[str]:
        """Load all NexPlugin subclasses from a single .py file."""
        spec   = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        loaded = []
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, NexPlugin) and obj is not NexPlugin
                    and obj.name):
                instance = obj()
                try:
                    instance.setup()
                except Exception:
                    pass
                self._plugins[obj.name] = instance
                self._classes[obj.name] = obj
                loaded.append(obj.name)
                logger.debug(f"Plugin loaded: {obj.name} ({obj.platform}/{obj.category})")
        return loaded

    def reload(self) -> List[str]:
        """Hot-reload all plugins."""
        for p in self._plugins.values():
            try:
                p.teardown()
            except Exception:
                pass
        self._plugins.clear()
        self._classes.clear()
        return self.discover()

    def get(self, name: str) -> Optional[NexPlugin]:
        return self._plugins.get(name)

    def run(self, name: str, session, args: list) -> Optional[str]:
        """Execute a named plugin against a session."""
        plugin = self.get(name)
        if not plugin:
            raise KeyError(f"Plugin '{name}' not found")
        plugin._session = session
        try:
            from db import get_db
            plugin._db = get_db()
        except Exception:
            pass
        return plugin.run(session, args)

    def list_all(self) -> List[Dict[str, Any]]:
        return [p.meta() for p in self._plugins.values()]

    def __contains__(self, name: str):
        return name in self._plugins

    def __len__(self):
        return len(self._plugins)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL REGISTRY SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

registry = PluginRegistry()
