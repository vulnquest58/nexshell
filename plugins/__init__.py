#!/usr/bin/env python3
"""NexShell plugins package — auto-discovery on import."""
from pathlib import Path
import importlib
import inspect
import logging

logger = logging.getLogger('nexshell.plugins')

def autodiscover():
    """Load all plugins in this directory."""
    try:
        from core.plugin import registry
        plugin_dir = Path(__file__).parent
        loaded = []
        for f in sorted(plugin_dir.glob('*.py')):
            if f.name.startswith('_'):
                continue
            try:
                names = registry._load_file(f)
                loaded.extend(names)
            except Exception as e:
                logger.debug(f"Plugin load error ({f.name}): {e}")
        if loaded:
            logger.info(f"Auto-discovered plugins: {loaded}")
        return loaded
    except Exception as e:
        logger.debug(f"Plugin autodiscover error: {e}")
        return []
