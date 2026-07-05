#!/usr/bin/env python3
"""NexShell db package — exports NexDB singleton."""
from .database import NexDB, get_db

__all__ = ['NexDB', 'get_db']
