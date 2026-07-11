"""
Port Allocator — Thread-safe port allocation for sessions and services.
"""

import socket
import threading
from typing import Set, Optional, List
from dataclasses import dataclass


@dataclass
class PortRange:
    start: int
    end: int

    def __post_init__(self):
        if self.start > self.end:
            raise ValueError("start must be <= end")
        if self.start < 1 or self.end > 65535:
            raise ValueError("ports must be 1-65535")


class PortAllocator:
    SHARE_RANGE    = PortRange(9001, 9100)   # File sharing (tools/)
    SESSION_RANGE  = PortRange(4000, 4999)   # Reverse shells
    LISTENER_RANGE = PortRange(5000, 5999)   # Listeners

    def __init__(self):
        self._allocated: Set[int] = set()
        self._lock = threading.Lock()

    # ── Public API ───────────────────────────────────────────────────────────

    def allocate_port(self, port_range: PortRange = None,
                      exclude: Set[int] = None) -> Optional[int]:
        if port_range is None:
            port_range = self.SESSION_RANGE
        exclude = exclude or set()
        with self._lock:
            for port in range(port_range.start, port_range.end + 1):
                if port not in self._allocated and port not in exclude:
                    if self._available(port):
                        self._allocated.add(port)
                        return port
        return None

    def allocate_share_port(self) -> Optional[int]:
        return self.allocate_port(self.SHARE_RANGE)

    def allocate_session_port(self) -> Optional[int]:
        return self.allocate_port(self.SESSION_RANGE)

    def allocate_listener_port(self) -> Optional[int]:
        return self.allocate_port(self.LISTENER_RANGE)

    def release_port(self, port: int):
        with self._lock:
            self._allocated.discard(port)

    def is_allocated(self, port: int) -> bool:
        with self._lock:
            return port in self._allocated

    def get_allocated(self) -> Set[int]:
        with self._lock:
            return self._allocated.copy()

    def available_in_range(self, port_range: PortRange) -> List[int]:
        return [
            p for p in range(port_range.start, port_range.end + 1)
            if not self.is_allocated(p) and self._available(p)
        ]

    def reset(self):
        with self._lock:
            self._allocated.clear()

    # ── Internal ─────────────────────────────────────────────────────────────

    @staticmethod
    def _available(port: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.close()
            return True
        except OSError:
            return False
