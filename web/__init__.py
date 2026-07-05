#!/usr/bin/env python3
"""web/__init__.py — Web package."""
from web.server import (
    DashboardServer,
    DashboardData,
    start_dashboard,
    stop_dashboard,
    get_dashboard,
)

__all__ = [
    'DashboardServer', 'DashboardData',
    'start_dashboard', 'stop_dashboard', 'get_dashboard',
]
