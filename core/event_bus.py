#!/usr/bin/env python3
"""
NexShell — Core Event Bus  (core/event_bus.py)
Async/threaded event dispatcher: Session → DB → Plugins → Logger.
All components communicate via events without direct coupling.

Usage:
    from core.event_bus import bus, Event

    # Subscribe
    bus.on('session.connected', my_handler)

    # Publish
    bus.emit('session.connected', session_id=1, host='10.0.0.1')
"""

import threading
import logging
import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger('nexshell.events')


# ══════════════════════════════════════════════════════════════════════════════
#  EVENT
# ══════════════════════════════════════════════════════════════════════════════

class Event:
    """Immutable event object passed to all handlers."""

    def __init__(self, name: str, **data):
        self.name      = name
        self.data      = data
        self.ts        = datetime.datetime.utcnow().isoformat()
        self._stopped  = False  # stop propagation flag

    def stop(self):
        """Stop propagation to remaining handlers."""
        self._stopped = True

    def __repr__(self):
        return f"Event({self.name!r}, {self.data})"


# ══════════════════════════════════════════════════════════════════════════════
#  EVENT BUS
# ══════════════════════════════════════════════════════════════════════════════

class EventBus:
    """
    Thread-safe pub/sub event dispatcher.

    - Handlers are called in registration order.
    - Async handlers run in a background thread (non-blocking).
    - sync=True emits synchronously (blocks until all handlers done).
    """

    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = {}
        self._wildcard: List[Callable]             = []
        self._lock      = threading.RLock()
        self._history:  List[Event]                = []
        self._max_hist  = 500

    # ── Registration ──────────────────────────────────────────────────────────

    def on(self, event_name: str, handler: Callable):
        """Register a handler for a specific event name."""
        with self._lock:
            self._handlers.setdefault(event_name, []).append(handler)

    def on_any(self, handler: Callable):
        """Register a handler for ALL events (wildcard)."""
        with self._lock:
            self._wildcard.append(handler)

    def off(self, event_name: str, handler: Callable):
        """Unregister a handler."""
        with self._lock:
            handlers = self._handlers.get(event_name, [])
            if handler in handlers:
                handlers.remove(handler)

    # ── Emission ──────────────────────────────────────────────────────────────

    def emit(self, event_name: str, sync: bool = False, **data) -> Event:
        """
        Emit an event. By default runs handlers in a background thread.
        Pass sync=True to block until all handlers finish.
        """
        event = Event(event_name, **data)
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_hist:
                self._history = self._history[-self._max_hist:]
            handlers = (
                list(self._handlers.get(event_name, [])) +
                list(self._wildcard)
            )

        if sync:
            self._dispatch(event, handlers)
        else:
            t = threading.Thread(
                target=self._dispatch,
                args=(event, handlers),
                daemon=True,
                name=f'nxsh-event-{event_name}'
            )
            t.start()
        return event

    def _dispatch(self, event: Event, handlers: list):
        for handler in handlers:
            if event._stopped:
                break
            try:
                handler(event)
            except Exception as e:
                logger.debug(f"Event handler error [{event.name}]: {e}")

    # ── History ───────────────────────────────────────────────────────────────

    def history(self, name_filter: Optional[str] = None) -> List[Event]:
        with self._lock:
            if name_filter:
                return [e for e in self._history if e.name == name_filter]
            return list(self._history)

    def clear_history(self):
        with self._lock:
            self._history.clear()


# ══════════════════════════════════════════════════════════════════════════════
#  PREDEFINED EVENT NAMES
# ══════════════════════════════════════════════════════════════════════════════

class Events:
    """Event name constants — prevents typos."""

    # Session lifecycle
    SESSION_CONNECTED   = 'session.connected'
    SESSION_UPGRADED    = 'session.upgraded'
    SESSION_DISCONNECTED= 'session.disconnected'
    SESSION_KILLED      = 'session.killed'
    SESSION_TAGGED      = 'session.tagged'

    # Loot
    LOOT_FOUND          = 'loot.found'
    LOOT_SCANNED        = 'loot.scanned'

    # Commands
    COMMAND_SENT        = 'command.sent'
    COMMAND_OUTPUT      = 'command.output'

    # Operations
    OPERATION_CREATED   = 'operation.created'
    OPERATION_OPENED    = 'operation.opened'
    OPERATION_ARCHIVED  = 'operation.archived'

    # Listeners
    LISTENER_STARTED    = 'listener.started'
    LISTENER_STOPPED    = 'listener.stopped'

    # Findings
    FINDING_CREATED     = 'finding.created'

    # Evidence
    EVIDENCE_ADDED      = 'evidence.added'

    # Health
    HEALTH_WARNING      = 'health.warning'
    HEALTH_CRITICAL     = 'health.critical'


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL BUS SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

bus = EventBus()
