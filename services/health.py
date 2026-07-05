#!/usr/bin/env python3
"""
NexShell — Health Monitor + Analytics  (services/health.py)
Monitors platform health (CPU/RAM/sessions/listeners/DB) and
computes engagement analytics (session durations, OS distribution, etc.).

CLI:
    health
    stats
    stats timeline
"""

import os
import time
import datetime
import threading
import platform
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH MONITOR
# ══════════════════════════════════════════════════════════════════════════════

class HealthMonitor:
    """
    Monitors NexShell platform health in real-time.
    Emits health.warning and health.critical events via EventBus.
    """

    def __init__(self):
        self._start_time = time.time()
        self._warnings:  List[str] = []
        self._thread:    Optional[threading.Thread] = None
        self._stop_ev    = threading.Event()
        self._interval   = 60   # check every 60s

    def start_background(self):
        """Start background health monitoring thread."""
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name='nxsh-health'
        )
        self._thread.start()

    def stop(self):
        self._stop_ev.set()

    def _monitor_loop(self):
        while not self._stop_ev.wait(self._interval):
            report = self.collect()
            if report.get('warnings'):
                try:
                    from core.event_bus import bus, Events
                    for w in report['warnings']:
                        bus.emit(Events.HEALTH_WARNING, message=w)
                except Exception:
                    pass

    def collect(self) -> Dict[str, Any]:
        """Collect current health metrics."""
        report: Dict[str, Any] = {
            'uptime_s':  int(time.time() - self._start_time),
            'platform':  platform.system(),
            'python':    platform.python_version(),
            'warnings':  [],
        }

        # CPU / Memory (optional — psutil not required)
        try:
            import psutil
            report['cpu_pct']   = psutil.cpu_percent(interval=0.1)
            report['ram_pct']   = psutil.virtual_memory().percent
            report['ram_used']  = psutil.virtual_memory().used // (1024*1024)
            report['ram_total'] = psutil.virtual_memory().total // (1024*1024)
            if report['cpu_pct'] > 90:
                report['warnings'].append(f"HIGH CPU: {report['cpu_pct']}%")
            if report['ram_pct'] > 90:
                report['warnings'].append(f"HIGH RAM: {report['ram_pct']}%")
        except ImportError:
            report['cpu_pct']   = 'n/a (install psutil)'
            report['ram_pct']   = 'n/a'
            report['ram_used']  = 'n/a'
            report['ram_total'] = 'n/a'

        # Sessions + Listeners
        try:
            from db import get_db
            db    = get_db()
            stats = db.stats()
            report['sessions_active']  = stats.get('sessions_active', 0)
            report['sessions_total']   = stats.get('sessions_total', 0)
            report['loot_total']       = stats.get('loot_total', 0)
            report['loot_creds']       = stats.get('loot_creds', 0)
            report['listeners_active'] = stats.get('listeners_active', 0)
            report['db_path']          = str(db.db_path)
            report['db_size_kb']       = int(db.db_path.stat().st_size / 1024)
        except Exception as e:
            report['db_error'] = str(e)

        # Plugins
        try:
            from core.plugin import registry
            report['plugins_loaded'] = len(registry)
        except Exception:
            report['plugins_loaded'] = 0

        return report

    def format_report(self) -> str:
        """Pretty-print health report for CLI."""
        r = self.collect()
        uptime = str(datetime.timedelta(seconds=r['uptime_s']))

        lines = [
            "\n  ╔══════════════════════════════════════════════╗",
            "  ║          NexShell Platform Health            ║",
            "  ╚══════════════════════════════════════════════╝",
            f"  Uptime          : {uptime}",
            f"  Platform        : {r['platform']} / Python {r['python']}",
            "",
            f"  CPU             : {r.get('cpu_pct', 'n/a')}",
            f"  RAM             : {r.get('ram_used', 'n/a')} MB / {r.get('ram_total', 'n/a')} MB ({r.get('ram_pct', 'n/a')}%)",
            "",
            f"  Sessions Active : {r.get('sessions_active', '—')}",
            f"  Sessions Total  : {r.get('sessions_total', '—')}",
            f"  Listeners       : {r.get('listeners_active', '—')}",
            f"  Loot Items      : {r.get('loot_total', '—')}  (creds: {r.get('loot_creds', '—')})",
            f"  Plugins Loaded  : {r.get('plugins_loaded', 0)}",
            "",
            f"  Database        : {r.get('db_path', '—')}  ({r.get('db_size_kb', '—')} KB)",
        ]
        if r.get('warnings'):
            lines.append("\n  ⚠️  Warnings:")
            for w in r['warnings']:
                lines.append(f"     • {w}")
        elif not r.get('db_error'):
            lines.append("\n  ✅  All systems nominal")
        if r.get('db_error'):
            lines.append(f"\n  ❌  DB Error: {r['db_error']}")
        lines.append("")
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  ANALYTICS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class AnalyticsEngine:
    """
    Computes engagement statistics from the DB.
    Session durations, OS distribution, credential types, timeline.
    """

    def compute(self) -> Dict[str, Any]:
        """Pull analytics from DB."""
        stats: Dict[str, Any] = {
            'generated': datetime.datetime.utcnow().isoformat(),
        }
        try:
            from db import get_db
            db = get_db()
            sessions = db.list_sessions()

            # Session stats
            durations = []
            os_dist:   Dict[str, int] = {}
            user_dist: Dict[str, int] = {}
            root_count = 0

            for s in sessions:
                os_dist[s.get('os', 'Unknown')] = os_dist.get(s.get('os', 'Unknown'), 0) + 1
                user = s.get('user', 'unknown') or 'unknown'
                user_dist[user] = user_dist.get(user, 0) + 1
                if s.get('is_root'):
                    root_count += 1
                # Duration calculation
                if s.get('connected_at') and s.get('last_seen'):
                    try:
                        fmt = '%Y-%m-%d %H:%M:%S'
                        t1 = datetime.datetime.strptime(s['connected_at'][:19], fmt)
                        t2 = datetime.datetime.strptime(s['last_seen'][:19], fmt)
                        durations.append((t2 - t1).total_seconds())
                    except Exception:
                        pass

            stats['sessions_total']   = len(sessions)
            stats['sessions_root']    = root_count
            stats['os_distribution']  = os_dist
            stats['avg_duration_min'] = round(sum(durations) / len(durations) / 60, 1) if durations else 0

            # Loot stats
            loot_summary = db.get_loot_summary()
            stats['loot_by_category'] = loot_summary
            stats['loot_total']       = sum(loot_summary.values())

        except Exception as e:
            stats['error'] = str(e)

        return stats

    def format_report(self) -> str:
        """Pretty analytics report for CLI."""
        s = self.compute()
        lines = [
            "\n  ╔══════════════════════════════════════════════╗",
            "  ║          NexShell Engagement Analytics       ║",
            "  ╚══════════════════════════════════════════════╝",
            f"  Generated: {s['generated'][:19]}",
            "",
            f"  Sessions Total    : {s.get('sessions_total', 0)}",
            f"  Sessions w/ Root  : {s.get('sessions_root', 0)}",
            f"  Avg Session Dur.  : {s.get('avg_duration_min', 0)} min",
            f"  Total Loot Items  : {s.get('loot_total', 0)}",
        ]

        os_dist = s.get('os_distribution', {})
        if os_dist:
            lines.append("\n  OS Distribution:")
            for os_name, count in sorted(os_dist.items(), key=lambda x: -x[1]):
                bar = '█' * min(count, 30)
                lines.append(f"    {os_name:<15} {bar} {count}")

        loot_dist = s.get('loot_by_category', {})
        if loot_dist:
            lines.append("\n  Loot by Category:")
            for cat, count in sorted(loot_dist.items(), key=lambda x: -x[1]):
                bar = '█' * min(count * 2, 30)
                lines.append(f"    {cat:<20} {bar} {count}")

        if s.get('error'):
            lines.append(f"\n  ⚠️  {s['error']}")
        lines.append("")
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL SINGLETONS
# ══════════════════════════════════════════════════════════════════════════════

health    = HealthMonitor()
analytics = AnalyticsEngine()
