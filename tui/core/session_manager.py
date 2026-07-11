"""
Session Manager — Manages active connections and sessions.
"""

import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
from datetime import datetime
from enum import Enum


class SessionStatus(Enum):
    PENDING      = "pending"
    CONNECTED    = "connected"
    DISCONNECTED = "disconnected"
    ERROR        = "error"


@dataclass
class Session:
    session_id:    str
    target_ip:     str
    target_port:   int
    local_port:    int
    status:        SessionStatus = SessionStatus.PENDING
    connected_at:  Optional[datetime] = None
    last_activity: Optional[datetime] = None
    tty_upgraded:  bool = False
    metadata:      Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "session_id":   self.session_id,
            "target_ip":    self.target_ip,
            "target_port":  self.target_port,
            "local_port":   self.local_port,
            "status":       self.status.value,
            "connected_at": self.connected_at.isoformat() if self.connected_at else None,
            "tty_upgraded": self.tty_upgraded,
        }


class SessionManager:
    def __init__(self):
        self.sessions:  Dict[str, Session] = {}
        self._lock:     threading.Lock = threading.Lock()
        self._listeners: List[Callable] = []
        self._counter:  int = 0

    def create_session(self, target_ip: str, target_port: int, local_port: int) -> Session:
        with self._lock:
            self._counter += 1
            sid = f"session_{self._counter}_{int(time.time())}"
            session = Session(
                session_id=sid,
                target_ip=target_ip,
                target_port=target_port,
                local_port=local_port,
            )
            self.sessions[sid] = session
            self._notify("session_created", session)
            return session

    def update_status(self, session_id: str, status: SessionStatus):
        with self._lock:
            if session_id in self.sessions:
                s = self.sessions[session_id]
                s.status = status
                s.last_activity = datetime.utcnow()
                if status == SessionStatus.CONNECTED and not s.connected_at:
                    s.connected_at = datetime.utcnow()
                self._notify("session_updated", s)

    def mark_tty_upgraded(self, session_id: str):
        with self._lock:
            if session_id in self.sessions:
                self.sessions[session_id].tty_upgraded = True
                self._notify("tty_upgraded", self.sessions[session_id])

    def get_active_session(self) -> Optional[Session]:
        with self._lock:
            for s in self.sessions.values():
                if s.status == SessionStatus.CONNECTED:
                    return s
            return None

    def get_session(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self.sessions.get(session_id)

    def get_all_sessions(self) -> List[Session]:
        with self._lock:
            return list(self.sessions.values())

    def remove_session(self, session_id: str):
        with self._lock:
            if session_id in self.sessions:
                s = self.sessions.pop(session_id)
                self._notify("session_removed", s)

    def has_active_connection(self) -> bool:
        return self.get_active_session() is not None

    def add_listener(self, cb: Callable):
        self._listeners.append(cb)

    def _notify(self, event: str, session: Session):
        for cb in self._listeners:
            try:
                cb(event, session)
            except Exception:
                pass

    def get_session_count(self) -> int:
        with self._lock:
            return len(self.sessions)

    def get_connected_count(self) -> int:
        with self._lock:
            return sum(1 for s in self.sessions.values()
                       if s.status == SessionStatus.CONNECTED)
